package org.rubigdata

import org.apache.spark.SparkConf
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions._
import org.jsoup.Jsoup
import collection.JavaConverters._

object RUBigDataApp {
  def main(args: Array[String]) {

    val sparkConf = new SparkConf().setAppName("RUBigData VulnJS 2026")
    val spark = SparkSession.builder().config(sparkConf).getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    import spark.implicits._

    // Point at a glob of WARC files
    val warcfile = "hdfs:///single-warc-segment/CC-MAIN-20210410105831-20210410135831-000{00,01,02,03,04,05,06,07,08,09,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99}.warc.gz"

    // Load WARC files, parse HTTP, keep HTML responses only
    val htmlPages = spark
      .read
      .format("org.rubigdata.warc")
      .option("parseHTTP", true)
      .load(warcfile)
      .filter($"warcType" === "response")
      .filter($"httpHeaders.Content-Type"(0).startsWith("text/html"))
      .select("warcTargetUri", "httpBody")
      .filter(length($"httpBody") > 0)
      .cache()

    // Extract <script src="..."> tags using Jsoup
    val extractScriptSrcs = udf((html: String) => {
      if (html == null || html.isEmpty) Seq.empty[String]
      else Jsoup.parse(html).select("script[src]").asScala.map(_.attr("src")).toSeq
    })

    val scriptSrcs = htmlPages
      .select(
        $"warcTargetUri",
        explode(extractScriptSrcs($"httpBody")).as("scriptSrc")
      )
      .filter(length($"scriptSrc") > 0)

    // Match against vulnerable library version patterns
    val vulnPattern = """(?i)(jquery[/\-](1\.|2\.|3\.[0-4]\.)|angular(\.min)?\.js|angular[/\-]1\.|bootstrap[/\-](2\.|3\.[0-3]\.|4\.[0-2]\.)|lodash[/\-](4\.17\.(0?[0-9]|1[0-9]|20)\.|[0-3]\.)|handlebars[/\-](2\.|3\.|4\.[0-6]\.|4\.7\.[0-6]))"""

    val vulnerable = scriptSrcs
      .filter($"scriptSrc".rlike(vulnPattern))
      .withColumn("library",
        when($"scriptSrc".rlike("(?i)jquery"),      lit("jQuery"))
        .when($"scriptSrc".rlike("(?i)angular"),    lit("AngularJS"))
        .when($"scriptSrc".rlike("(?i)bootstrap"),  lit("Bootstrap"))
        .when($"scriptSrc".rlike("(?i)lodash"),     lit("Lodash"))
        .when($"scriptSrc".rlike("(?i)handlebars"), lit("Handlebars"))
        .otherwise(lit("Other"))
      )
      .withColumn("version",
        regexp_extract($"scriptSrc", "(?i)(?:jquery|angular|bootstrap|lodash|handlebars)[^0-9]*(\\d+\\.\\d+\\.\\d+)", 1)
      )
      .withColumn("tld",
        regexp_extract($"warcTargetUri", "https?://[^/]*\\.([a-zA-Z]{2,6})(?:[:/]|$)", 1)
      )
      .withColumn("domain",
        regexp_extract($"warcTargetUri", "https?://([^/]+)", 1)
      )
      .withColumn("protocol",
        regexp_extract($"warcTargetUri", "^(https?)", 1)
      )
      .withColumn("cve",
        when($"library" === "jQuery" && $"version".startsWith("1."), lit("CVE-2019-11358"))
        .when($"library" === "jQuery" && $"version".startsWith("2."), lit("CVE-2020-11022"))
        .when($"library" === "jQuery" && $"version".startsWith("3."), lit("CVE-2020-11022"))
        .when($"library" === "AngularJS", lit("CVE-2020-7676"))
        .when($"library" === "Bootstrap", lit("CVE-2019-8331"))
        .when($"library" === "Lodash",    lit("CVE-2021-23337"))
        .when($"library" === "Handlebars",lit("CVE-2021-23369"))
        .otherwise(lit("other"))
      )
      .cache()

    val totalPages   = htmlPages.select("warcTargetUri").distinct().count()
    val affectedPages = vulnerable.select("warcTargetUri").distinct().count()

    println("\n########## VULNERABLE JS LIBRARY DETECTION ##########")
    println(s"Total HTML pages processed: $totalPages")
    println(s"Pages with a vulnerable library: $affectedPages")
    println(f"Fraction affected: ${affectedPages.toDouble / totalPages * 100}%.1f%%")

    println("\n=== Breakdown by library and version ===")
    vulnerable.groupBy("library", "version").count().orderBy(desc("count")).show(30)

    println("\n=== Pages affected per TLD ===")
    vulnerable
      .filter($"tld" =!= "")
      .groupBy("tld", "library")
      .agg(countDistinct("warcTargetUri").as("unique_pages"))
      .orderBy(desc("unique_pages"))
      .show(30)

    println("\n=== Top domains with most vulnerable pages ===")
    vulnerable
      .filter($"domain" =!= "")
      .groupBy("domain", "library")
      .agg(countDistinct("warcTargetUri").as("vulnerable_pages"))
      .orderBy(desc("vulnerable_pages"))
      .show(20, 80)

    println("\n=== CDN vs self-hosted vulnerable libraries ===")
    vulnerable
      .withColumn("source",
        when($"scriptSrc".startsWith("http"), lit("external CDN"))
        .otherwise(lit("self-hosted"))
      )
      .groupBy("source").count().show()

    println("\n=== Most prevalent CVEs ===")
    vulnerable.groupBy("cve").count().orderBy(desc("count")).show()

    println("\n=== HTTP vs HTTPS pages with vulnerable libraries ===")
    vulnerable
      .filter($"protocol" =!= "")
      .groupBy("protocol", "library")
      .count()
      .orderBy(desc("count"))
      .show()

    println("########### END ############\n")

    spark.stop()
  }
}
