# Detecting Vulnerable JavaScript Libraries in Common Crawl Web Data

A Spark/Scala data pipeline that scans a segment of the [Common Crawl](https://commoncrawl.org/) web archive for HTML pages that still load known-**vulnerable versions of popular JavaScript libraries** (jQuery, AngularJS, Bootstrap, Lodash, Handlebars), and quantifies how widespread the exposure is.

Radboud University — Big Data (NWI-IBC036) — s1122062, Levente Bódi

**Key finding:** of 4,802,842 HTML pages processed from the CC-MAIN-2021-17 crawl (100 WARC files, ~120 GB), **1,212,225 pages (25.2%)** loaded at least one JavaScript library version with a known CVE. jQuery dominated, with CVE-2019-11358 (prototype pollution) alone appearing on over 835,000 pages. Full analysis, methodology, and discussion in [`reports/report.pdf`](reports/report.pdf).

## How it works

The pipeline (`src/main/scala/org/rubigdata/RUBigDataApp.scala`) runs on Apache Spark and:

1. Loads WARC files from `hdfs:///single-warc-segment/...` using the [`warc-for-spark`](https://github.com/rubigdata/warc-for-spark) data source and keeps only `text/html` HTTP responses.
2. Extracts every `<script src="...">` reference from each page's HTML using [Jsoup](https://jsoup.org/).
3. Matches script URLs against a regex of known-vulnerable version ranges for jQuery, AngularJS, Bootstrap, Lodash, and Handlebars, and tags each match with its library, version, and primary CVE.
4. Aggregates results: breakdown by library/version, exposure by TLD, top affected domains, CDN-hosted vs. self-hosted, CVE frequency, and HTTP vs. HTTPS delivery.

`notebooks/warc_for_spark.zpln` is the Apache Zeppelin notebook used for interactive development/exploration before the job was packaged for cluster submission.

| Library | Vulnerable versions | Primary CVE |
|---|---|---|
| jQuery | 1.x, 2.x, 3.0–3.4.x | CVE-2019-11358, CVE-2020-11022 |
| AngularJS | 1.x | CVE-2020-7676 |
| Bootstrap | 2.x, 3.0–3.3.x, 4.0–4.2.x | CVE-2019-8331 |
| Lodash | < 4.17.21 | CVE-2021-23337 |
| Handlebars | < 4.7.7 | CVE-2021-23369 |

## Requirements

This is a **Scala + Apache Spark** project — see [`requirements.txt`](requirements.txt) for details (there are no Python dependencies).

- **JDK 8 or 11** and **sbt** (build tool)
- **Apache Spark 3.5.5** and **Hadoop 3.4.1** client libraries (declared `provided` in `build.sbt`; assumed to be supplied by the cluster/runtime)
- Network access to resolve `com.github.rubigdata:warc-for-spark` via [JitPack](https://jitpack.io/)
- A Hadoop/HDFS cluster (or local Spark with local WARC files) hosting a Common Crawl segment — this project was run against the Radboud "redbad" HDFS cluster's `/single-warc-segment/` path (CC-MAIN-2021-17). To reproduce it elsewhere, download WARC files from the [Common Crawl index](https://commoncrawl.org/get-started) and point the `warcfile` path in `RUBigDataApp.scala` at your own storage.

## Build & run

```bash
sbt assembly
spark-submit \
  --class org.rubigdata.RUBigDataApp \
  --deploy-mode cluster \
  target/scala-2.12/RUBigDataApp-assembly-1.0.jar
```

## Project layout

```
build.sbt
src/main/scala/org/rubigdata/RUBigDataApp.scala   # the Spark job
notebooks/warc_for_spark.zpln                      # exploratory Zeppelin notebook
reports/report.pdf                                 # full write-up: methodology, results, lessons learned
```

## License

MIT — see [LICENSE](LICENSE).
