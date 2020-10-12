const AWS = require("aws-sdk");
const cw = new AWS.CloudWatch({ apiVersion: "2010-08-01" });
const cb = new AWS.CodeBuild({ apiVersion: "2016-10-06" });
const now = Date.now();

const putMetric = async ({
  seconds = 0,
  projectName,
  ns = "proofs",
  buildStatus = "MISSING",
}) =>
  await cw
    .putMetricData({
      Namespace: ns,
      MetricData: [
        {
          MetricName: "SecondsSinceLastCompletedRun",
          Unit: "Seconds",
          Value: seconds,
          Timestamp: new Date(now),
          Dimensions: [
            { Name: "projectName", Value: projectName },
            { Name: "buildStatus", Value: buildStatus },
          ],
        },
      ],
    })
    .promise();

exports.handler = async (event, _context) => {
  const { projectName } = event;
  const buildIDs = await cb
    .listBuildsForProject({
      projectName,
      sortOrder: "DESCENDING",
    })
    .promise();

  if (buildIDs.$response.error) return putMetric({ projectName });

  const batchBuilds = await cb.batchGetBuilds({ ids: buildIDs.ids }).promise();
  if (batchBuilds.$response.error) return putMetric({ projectName });

  const builds = batchBuilds.builds.filter((b) => !!b.endTime);
  if (!builds.length) return putMetric({ projectName });

  const build = builds[0];
  const secondsSinceLastCompletedRun = Math.floor(
    (now - Date.parse(build.endTime)) / 1000
  );
  return putMetric({
    seconds: secondsSinceLastCompletedRun,
    projectName,
    buildStatus: build.buildStatus,
  });
};
