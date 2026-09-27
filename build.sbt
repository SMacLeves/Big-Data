name            := "RUBigDataApp"
organization    := "org.rubigdata"
version         := "1.0"
scalaVersion    := "2.12.10"

val sparkV      = "3.5.5"
val hadoopV     = "3.4.1"

Compile / packageBin / mainClass := Some(organization.value + "." + name.value)
assembly / mainClass             := Some(organization.value + "." + name.value)

resolvers += "jitpack" at "https://jitpack.io"

libraryDependencies ++= Seq(
  "org.apache.spark"     %% "spark-core"       % sparkV  % "provided",
  "org.apache.spark"     %% "spark-sql"        % sparkV  % "provided",
  "org.apache.hadoop"    %  "hadoop-client"    % hadoopV % "provided",
  "com.github.rubigdata" %  "warc-for-spark"   % "0.3.0",
  "org.jsoup"            %  "jsoup"            % "1.11.3",
  "org.netpreserve"      %  "jwarc"            % "0.30.0"
)

assembly / assemblyMergeStrategy := {
  case PathList("org", "bouncycastle", _*) => MergeStrategy.first
  case PathList("META-INF", _*)            => MergeStrategy.discard
  case "reference.conf"                    => MergeStrategy.concat
  case _                                   => MergeStrategy.first
}
