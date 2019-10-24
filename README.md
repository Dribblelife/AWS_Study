[TOC]
#   boto3学习

##  boto3是什么？
>Boto允许大家编写部分脚本，从而以自动化方式实现AWS EC2实例启动等常见操作。 

>Boto是一套Python软件包，旨在将编程性连接引入Amazon Web Services当中。

>大家可以通过AWS控制台或者利用AWS的扩展API对这些服务加以控制。不过除此之外，大家还可以利用多种第三方库使用该API。在Python领域，我们可以选择Boto。Boto允许用户编写各种便利的脚本方案，从而以自动化方式实现多种常见操作，例如启动或停止EC2实例，或者定期为服务器保存快照等。



##  boto3准备
-   安装boto3和awscli

我这里直接在pycharm下的venv安装，分别安装boto3和awscli

-   配置aws configure
需要aws账户以及设置身份验证凭据




##  代码范例

### Amazon CloudWatch （监控报警）
-   1、创建警报

（1）描述警报
```py
import boto3

# Create CloudWatch client
cloudwatch = boto3.client('cloudwatch')

# List alarms of insufficient data through the pagination interface
# 通过接口列出数据不足的警报

paginator = cloudwatch.get_paginator('describe_alarms')
for response in paginator.paginate(StateValue='INSUFFICIENT_DATA'):
    print(response['MetricAlarms'])
```
（2）为CloudWatch指标警报创建警报,这里示例为cpu监控警报。
```py
import boto3

# Create CloudWatch client
cloudwatch = boto3.client('cloudwatch')

# Create alarm
cloudwatch.put_metric_alarm(
    AlarmName='Web_Server_CPU_Utilization',
    ComparisonOperator='GreaterThanThreshold',
    EvaluationPeriods=1,
    MetricName='CPUUtilization',
    Namespace='AWS/EC2',
    Period=60,
    Statistic='Average',
    Threshold=70.0,
    ActionsEnabled=False,
    AlarmDescription='Alarm when server CPU exceeds 70%',
    Dimensions=[
        {
          'Name': 'InstanceId',
          'Value': 'INSTANCE_ID'
        },
    ],
    Unit='Seconds'
)
```
（3）删除警报
```py
import boto3

# Create CloudWatch client
cloudwatch = boto3.client('cloudwatch')

# Delete alarm
cloudwatch.delete_alarms(
  AlarmNames=['Web_Server_CPU_Utilization'],
)g
```

-   2、使用警报操作

（1）创建一个IAM角色，该角色的策略将授予描述，重新引导，停止或终止Amazon EC2实例的权限。

（2）创建或更新警报并将其与指定的指标关联。（可选）此操作可以将一个或多个Amazon SNS资源与警报关联。
```py
import boto3

# Create CloudWatch client
cloudwatch = boto3.client('cloudwatch')

# Create alarm with actions enabled
cloudwatch.put_metric_alarm(
    AlarmName='Web_Server_CPU_Utilization',
    ComparisonOperator='GreaterThanThreshold',
    EvaluationPeriods=1,
    MetricName='CPUUtilization',
    Namespace='AWS/EC2',
    Period=60,
    Statistic='Average',
    Threshold=70.0,
    ActionsEnabled=True,
    AlarmActions=[
      'arn:aws:swf:us-west-2:{CUSTOMER_ACCOUNT}:action/actions/AWS_EC2.InstanceId.Reboot/1.0'
    ],
    AlarmDescription='Alarm when server CPU exceeds 70%',
    Dimensions=[
        {
          'Name': 'InstanceId',
          'Value': 'INSTANCE_ID'
        },
    ],
    Unit='Seconds'
)
```
（3）禁用警报动作
```py
import boto3

# Create CloudWatch client
cloudwatch = boto3.client('cloudwatch')

# Disable alarm
cloudwatch.disable_alarm_actions(
  AlarmNames=['Web_Server_CPU_Utilization'],
)
```




-   3、获取指标

（1）列出指标
```py
import boto3

# Create CloudWatch client
cloudwatch = boto3.client('cloudwatch')

# List metrics through the pagination interface
paginator = cloudwatch.get_paginator('list_metrics')
for response in paginator.paginate(Dimensions=[{'Name': 'LogGroupName'}],
                                   MetricName='IncomingLogEvents',
                                   Namespace='AWS/Logs'):
    print(response['Metrics'])
```
（2）发布自定义指标
> 将指标数据点发布到Amazon CloudWatch。Amazon CloudWatch将数据点与指定指标关联。如果指定的指标不存在，Amazon CloudWatch将创建该指标。Amazon CloudWatch创建指标时，该指标最多可能需要十五分钟才能显示在对ListMetrics的调用中。

```py
import boto3

# Create CloudWatch client
cloudwatch = boto3.client('cloudwatch')

# Put custom metrics
cloudwatch.put_metric_data(
    MetricData=[
        {
            'MetricName': 'PAGES_VISITED',
            'Dimensions': [
                {
                    'Name': 'UNIQUE_PAGES',
                    'Value': 'URLS'
                },
            ],
            'Unit': 'None',
            'Value': 1.0
        },
    ],
    Namespace='SITE/TRAFFIC'
)
```

-  4、将事件发送到Amazon CloudWatch事件

（1）创建一个预定规则，使用put_rule创建CloudWatch Events规则

```py
import boto3


# Create CloudWatchEvents client
cloudwatch_events = boto3.client('events')

# Put an event rule
response = cloudwatch_events.put_rule(
    Name='DEMO_EVENT',
    RoleArn='IAM_ROLE_ARN',
    ScheduleExpression='rate(5 minutes)',
    State='ENABLED'
)
print(response['RuleArn'])
```

（2）添加lambda函数目标，使用put_targets将目标添加到规则中。
```py
import boto3

# Create CloudWatchEvents client
cloudwatch_events = boto3.client('events')

# Put target for rule
response = cloudwatch_events.put_targets(
    Rule='DEMO_EVENT',
    Targets=[
        {
            'Arn': 'LAMBDA_FUNCTION_ARN',
            'Id': 'myCloudWatchEventsTarget',
        }
    ]
)
print(response)
```
（3）发送事件events，使用put_events将自定义事件发送到CloudWatch Events。
```py
import json

import boto3


# Create CloudWatchEvents client
cloudwatch_events = boto3.client('events')

# Put an event
response = cloudwatch_events.put_events(
    Entries=[
        {
            'Detail': json.dumps({'key1': 'value1', 'key2': 'value2'}),
            'DetailType': 'appRequestSubmitted',
            'Resources': [
                'RESOURCE_ARN',
            ],
            'Source': 'com.company.myapp'
        }
    ]
)
print(response['Entries'])
```

-   5、日志中使用订阅过滤器
（1）列出现有的订阅过滤器
列出指定日志组的订阅筛选器，使用`get_paginator（'describe_subscription_filters'）`列出订阅过滤器。

```py
import boto3

# Create CloudWatchLogs client
cloudwatch_logs = boto3.client('logs')

# List subscription filters through the pagination interface
paginator = cloudwatch_logs.get_paginator('describe_subscription_filters')
for response in paginator.paginate(logGroupName='GROUP_NAME'):
    print(response['subscriptionFilters'])
```
（2）创建订阅过滤器,并将其与指定的日志组关联。使用put_subscription_filter创建订阅过滤器 。
```py
import boto3

# Create CloudWatchLogs client
cloudwatch_logs = boto3.client('logs')

# Create a subscription filter
cloudwatch_logs.put_subscription_filter(
    destinationArn='LAMBDA_FUNCTION_ARN',
    filterName='FILTER_NAME',
    filterPattern='ERROR',
    logGroupName='LOG_GROUP',
)
```

（3）删除订阅过滤器。使用 delete_subscription_filter。
```py
import boto3

# Create CloudWatchLogs client
cloudwatch_logs = boto3.client('logs')

# Delete a subscription filter
cloudwatch_logs.delete_subscription_filter(
    filterName='FILTER_NAME',
    logGroupName='LOG_GROUP',
)
```

###  DynamoDB(NoSQL数据库)

-   1、创建新表

>为了创建一个新表，请使用 DynamoDB.ServiceResource.create_table（）方法：

```py
import boto3

# Get the service resource.
dynamodb = boto3.resource('dynamodb')

# Create the DynamoDB table.
table = dynamodb.create_table(
    TableName='users',
    KeySchema=[
        {
            'AttributeName': 'username',
            'KeyType': 'HASH'
        },
        {
            'AttributeName': 'last_name',
            'KeyType': 'RANGE'
        }
    ],
    AttributeDefinitions=[
        {
            'AttributeName': 'username',
            'AttributeType': 'S'
        },
        {
            'AttributeName': 'last_name',
            'AttributeType': 'S'
        },
    ],
    ProvisionedThroughput={
        'ReadCapacityUnits': 5,
        'WriteCapacityUnits': 5
    }
)

# Wait until the table exists.
table.meta.client.get_waiter('table_exists').wait(TableName='users')

# Print out some data about the table.
print(table.item_count)
```
这将创建一个名为users的表，该表分别具有哈希和范围主键username和last_name。此方法将返回DynamoDB.Table资源，以在创建的表上调用其他方法。

-   2、使用现有的表

```py
import boto3

# Get the service resource.
dynamodb = boto3.resource('dynamodb')

# Instantiate a table resource object without actually
# creating a DynamoDB table. Note that the attributes of this table
# are lazy-loaded: a request is not made nor are the attribute
# values populated until the attributes
# on the table resource are accessed or its load() method is called.
table = dynamodb.Table('users')

# Print out some data about the table.
# This will cause a request to be made to DynamoDB and its attribute
# values will be set based on the response.
print(table.creation_date_time)
```

-   3、创建新item

拥有DynamoDB.Table资源后，您可以使用DynamoDB.Table.put_item（）将新项目添加到表中：
```py
table.put_item(
   Item={
        'username': 'janedoe',
        'first_name': 'Jane',
        'last_name': 'Doe',
        'age': 25,
        'account_type': 'standard_user',
    }
)
```
-   4、获取一个item

然后，您可以使用DynamoDB.Table.get_item（）检索对象：
```py
response = table.get_item(
    Key={
        'username': 'janedoe',
        'last_name': 'Doe'
    }
)
item = response['Item']
print(item)
```
-   5、更新item
### 需要提问：
```py
table.update_item(
    Key={
        'username': 'janedoe',
        'last_name': 'Doe'
    },
    UpdateExpression='SET age = :val1', # 这一步的目的是？为何不直接操作age字段？
    ExpressionAttributeValues={
        ':val1': 26
    }
)
```
-   6、删除item
```py
table.delete_item(
    Key={
        'username': 'janedoe',
        'last_name': 'Doe'
    }
)
```
-   7、批处理
如果您一次加载大量数据，则可以使用 DynamoDB.Table.batch_writer（），这样既可以加快处理速度，又可以减少对服务的写入请求数。
```py
with table.batch_writer() as batch:
    batch.put_item(
        Item={
            'account_type': 'standard_user',
            'username': 'johndoe',
            'first_name': 'John',
            'last_name': 'Doe',
            'age': 25,
            'address': {
                'road': '1 Jefferson Street',
                'city': 'Los Angeles',
                'state': 'CA',
                'zipcode': 90001
            }
        }
    )
    batch.put_item(
        Item={
            'account_type': 'super_user',
            'username': 'janedoering',
            'first_name': 'Jane',
            'last_name': 'Doering',
            'age': 40,
            'address': {
                'road': '2 Washington Avenue',
                'city': 'Seattle',
                'state': 'WA',
                'zipcode': 98109
            }
        }
    )
```
>The batch writer is even able to handle a very large amount of writes to the table.
```py
with table.batch_writer() as batch:
    for i in range(50):
        batch.put_item(
            Item={
                'account_type': 'anonymous',
                'username': 'user' + str(i),
                'first_name': 'unknown',
                'last_name': 'unknown'
            }
        )
```

> de-duplicate 如果它们的主键（复合）值与新添加的主键（复合）值相同，它将最终将请求项放在缓冲区中，因为最终该值与同一项上各个放置/删除操作的流一致。

**这里不是很清楚？？？ 并没有太理解？？？**

-   8、查询与扫描
（1）需要导入类：`from boto3.dynamodb.conditions import Key,Attr`


```py
# 这将查询其用户名键等于johndoe的所有用户：

response = table.query(
    KeyConditionExpression=Key('username').eq('johndoe')
)
items = response['Items']
print(items)

# 同样，您可以根据项目的属性扫描表。例如，这将扫描年龄小于27 岁的所有用户：

response = table.scan(
    FilterExpression=Attr('age').lt(27)
)
items = response['Items']
print(items)

# 您还可以使用逻辑运算符将条件链接在一起： ＆（和），|。（或）和〜（不是）。例如，这将扫描first_name以J开头且account_type为 super_user的所有用户：

response = table.scan(
    FilterExpression=Attr('first_name').begins_with('J') & Attr('account_type').eq('super_user')
)
items = response['Items']
print(items)

# 您甚至可以根据嵌套属性的条件进行扫描。例如，这将扫描其地址中的状态为CA的所有用户：

response = table.scan(
    FilterExpression=Attr('address.state').eq('CA')
)
items = response['Items']
print(items)

```


-   9、删除表

如果要删除表，请调用 `DynamoDB.Table.delete()`
```py
table.delete()
```

### EC2示例
> Amazon Elastic Compute Cloud（Amazon EC2）是一项Web服务，可在Amazon数据中心的服务器中提供可调整大小的计算能力，可用于构建和托管软件系统。

####    管理EC2实例

-   1、描述实例（describe instances）

```py
import boto3

ec2 = boto3.client('ec2')
response = ec2.describe_instances()
print(response)
```
-   2、监视和取消监视实例
```py
import sys
import boto3


ec2 = boto3.client('ec2')
if sys.argv[1] == 'ON':
    response = ec2.monitor_instances(InstanceIds=['INSTANCE_ID'])
else:
    response = ec2.unmonitor_instances(InstanceIds=['INSTANCE_ID'])
print(response)
```
-   3、启动和停止实例
> 可以快速停止和启动使用Amazon EBS卷作为其根设备的实例。实例停止后，将释放计算资源，并且无需按小时计费。但是，您的根分区Amazon EBS卷将保留，并继续保留您的数据，并向Amazon EBS卷使用收取费用。您可以随时重新启动实例。每次将实例从停止状态转换为启动状态时，即使一次在一小时内发生多次转换，Amazon EC2也会收取完整的实例小时费用。
####   提问：也就是说EBS将一直收取费用？

```py
#  这里的作用不是特别理解？？？？？？
import sys
import boto3
from botocore.exceptions import ClientError

instance_id = sys.argv[2]
action = sys.argv[1].upper()

ec2 = boto3.client('ec2')

if action == 'ON':
    # Do a dryrun first to verify permissions
    try:
        ec2.start_instances(InstanceIds=[instance_id], DryRun=True)
    except ClientError as e:
        if 'DryRunOperation' not in str(e):
            raise

    # Dry run succeeded, run start_instances without dryrun
    try:
        response = ec2.start_instances(InstanceIds=[instance_id], DryRun=False)
        print(response)
    except ClientError as e:
        print(e)
else:
    # Do a dryrun first to verify permissions
    try:
        ec2.stop_instances(InstanceIds=[instance_id], DryRun=True)
    except ClientError as e:
        if 'DryRunOperation' not in str(e):
            raise

    # Dry run succeeded, call stop_instances without dryrun
    try:
        response = ec2.stop_instances(InstanceIds=[instance_id], DryRun=False)
        print(response)
    except ClientError as e:
        print(e)
```
-   4、重启实例
####    使用EC2密钥对
-   1、描述EC2密钥对
```py
import boto3

ec2 = boto3.client('ec2')
response = ec2.describe_key_pairs()
print(response)
```
-   2、创建一个密钥对
> 创建具有指定名称的2048位RSA密钥对。Amazon EC2存储公钥并显示私钥供您保存到文件。私钥作为未加密的PEM编码的PKCS＃8私钥返回。如果具有指定名称的密钥已经存在，Amazon EC2将返回错误。
```py
import boto3

ec2 = boto3.client('ec2')
response = ec2.create_key_pair(KeyName='KEY_PAIR_NAME')
print(response)
```
-   3、删除密钥对
> 通过从Amazon EC2删除公钥来删除指定的密钥对。通过使用delete_key_pair从Amazon EC2删除公钥来删除密钥对 。
```py
import boto3

ec2 = boto3.client('ec2')
response = ec2.delete_key_pair(KeyName='KEY_PAIR_NAME')
print(response)
```
####    描述EC2区域和可用区
> 描述您当前可用的一个或多个区域。
> 结果仅包括您当前正在使用的区域的区域。如果发生影响可用区的事件，则可以使用此请求来查看状态以及该可用区提供的任何消息。

以下示例显示了如何：
-   使用describe_regions描述区域。
-   使用describe_availability_zones描述AvailabilityZones 。
```py
import boto3

ec2 = boto3.client('ec2')

# Retrieves all regions/endpoints that work with EC2
response = ec2.describe_regions()
print('Regions:', response['Regions'])

# Retrieves availability zones only for region of the ec2 object
response = ec2.describe_availability_zones()
print('Availability Zones:', response['AvailabilityZones'])
```

####    在EC2中使用安全组
> Amazon EC2安全组充当虚拟防火墙，可控制一个或多个实例的流量。您将规则添加到每个安全组，以允许往返于其关联实例的流量。您可以随时修改安全组的规则。新规则将自动应用于与安全组关联的所有实例。


-   1、描述安全组
```py
import boto3
from botocore.exceptions import ClientError

ec2 = boto3.client('ec2')

try:
    response = ec2.describe_security_groups(GroupIds=['SECURITY_GROUP_ID'])
    print(response)
except ClientError as e:
    print(e)
```
-   2、创建一个安全组以访问EC2实例
>创建一个安全组。
>将一个或多个入口规则添加到安全组。
>规则更改将尽快传播到安全组内的实例。但是，可能会发生少量延迟。
```py
import boto3
from botocore.exceptions import ClientError

ec2 = boto3.client('ec2')

response = ec2.describe_vpcs()
vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

try:
    response = ec2.create_security_group(GroupName='SECURITY_GROUP_NAME',
                                         Description='DESCRIPTION',
                                         VpcId=vpc_id)
    security_group_id = response['GroupId']
    print('Security Group Created %s in vpc %s.' % (security_group_id, vpc_id))

    data = ec2.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 80,
             'ToPort': 80,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp',
             'FromPort': 22,
             'ToPort': 22,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
        ])
    print('Ingress Successfully Set %s' % data)
except ClientError as e:
    print(e)
```
-   3、删除现有的安全组
```py
import boto3
from botocore.exceptions import ClientError

# Create EC2 client
ec2 = boto3.client('ec2')

# Delete security group
try:
    response = ec2.delete_security_group(GroupId='SECURITY_GROUP_ID')
    print('Security Group Deleted')
except ClientError as e:
    print(e)
```

####    在EC2中使用弹性IP地址

-   1、描述弹性IP地址
> 弹性IP地址是为动态云计算设计的静态IPv4地址。弹性IP地址与您的AWS账户关联。使用弹性IP地址，可以通过将地址快速重新映射到帐户中的另一个实例来掩盖实例或软件的故障。
```py
import boto3


ec2 = boto3.client('ec2')
filters = [
    {'Name': 'domain', 'Values': ['vpc']}
]
response = ec2.describe_addresses(Filters=filters)
print(response)
```


-   2、将弹性IP地址分配并与EC2实例关联
```py
import boto3
from botocore.exceptions import ClientError

ec2 = boto3.client('ec2')

try:
    allocation = ec2.allocate_address(Domain='vpc')
    response = ec2.associate_address(AllocationId=allocation['AllocationId'],
                                     InstanceId='INSTANCE_ID')
    print(response)
except ClientError as e:
    print(e)
```
-   3、释放弹性IP地址
> 释放弹性IP地址后，它会释放到IP地址池中，并且可能对您不可用。确保更新您的DNS记录以及与该地址通信的所有服务器或设备。如果您尝试释放已经释放的弹性IP地址， 则如果该地址已经分配给另一个AWS账户，则会收到AuthFailure错误。

```py
import boto3
from botocore.exceptions import ClientError


ec2 = boto3.client('ec2')

try:
    response = ec2.release_address(AllocationId='ALLOCATION_ID')
    print('Address released')
except ClientError as e:
    print(e)
```
### IAM示例
> 该服务针对的是在云中具有多个用户或系统的组织，这些组织或系统使用AWS产品（例如Amazon EC2，Amazon SimpleDB和AWS Management Console）。借助IAM，您可以集中管理用户，安全凭证（例如访问密钥）以及控制用户可以访问哪些AWS资源的权限。

####    管理IAM用户
-   1、创建用户

```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Create user
response = iam.create_user(
    UserName='IAM_USER_NAME'
)

print(response)
```
-   2、列出账户中的用户
```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# List users with the pagination interface
paginator = iam.get_paginator('list_users')
for response in paginator.paginate():
    print(response)
```
-   3、更新用户名
```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Update a user name
iam.update_user(
    UserName='IAM_USER_NAME',
    NewUserName='NEW_IAM_USER_NAME'
)
```

-   4、删除用户
```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Delete a user
iam.delete_user(
    UserName='IAM_USER_NAME'
)
```
####    使用IAM策略
> 您可以通过创建策略来授予用户权限，该策略是一个文档，其中列出了用户可以执行的操作以及这些操作可能影响的资源。默认情况下，拒绝任何未明确允许的操作或资源。可以创建策略并将其附加到用户，用户组，用户承担的角色和资源

-   1、创建一个IAM策略
```py
import json

import boto3

# Create IAM client
iam = boto3.client('iam')

# Create a policy
my_managed_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "RESOURCE_ARN"
        },
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:DeleteItem",
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:Scan",
                "dynamodb:UpdateItem"
            ],
            "Resource": "RESOURCE_ARN"
        }
    ]
}
response = iam.create_policy(
  PolicyName='myDynamoDBPolicy',
  PolicyDocument=json.dumps(my_managed_policy)
)
print(response)
```
-   2、获取IAM策略
> 获取有关指定的托管策略的信息，包括策略的默认版本以及该策略所附加的IAM用户，组和角色的总数。
> 要获取该策略所附加的特定用户，组和角色的列表，请使用 list_entities_for_policy API。该API返回有关策略的元数据。
> 要获取特定版本策略的实际策略文档，请使用get_policy_version API。该API获取有关托管策略的信息。
> 要获取有关嵌入到IAM用户，组或角色中的内联策略的信息，请使用get_user_policy，get_group_policy或get_role_policy API。

```py
import boto3


# Create IAM client
iam = boto3.client('iam')

# Get a policy
response = iam.get_policy(
    PolicyArn='arn:aws:iam::aws:policy/AWSLambdaExecute'
)
print(response['Policy'])
```

-   3、附加托管角色策略

> 当您将托管策略附加到角色时，托管策略将成为角色的许可（访问）策略的一部分。您不能将托管策略用作角色的信任策略。使用create_role与角色同时创建角色的信任策略。您可以使用update_assume_role_policy更新角色的信任策略 。
>使用此API将托管策略附加到角色。要将嵌入式策略嵌入角色中，请使用put_role_policy。

```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Attach a role policy
iam.attach_role_policy(
    PolicyArn='arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess',
    RoleName='AmazonDynamoDBFullAccess'
)
```
-   4、分离托管角色策略
```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Detach a role policy
iam.detach_role_policy(
    PolicyArn='arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess',
    RoleName='AmazonDynamoDBFullAccess'
)
```

####    管理IAM访问密钥
> 用户需要自己的访问密钥，才能从适用于Python的Amazon Web Services（AWS）SDK进行对AWS的编程调用。为了满足此需求，您可以为IAM用户创建，修改，查看或旋转访问密钥（访问密钥ID和秘密访问密钥）。默认情况下，创建访问密钥时，其状态为“活动”，这意味着用户可以将访问密钥用于API调用。

-   1、为用户创建访问密钥
> 为指定用户创建一个新的AWS秘密访问密钥和相应的AWS访问密钥ID。新键的默认状态为Active。

```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Create an access key
response = iam.create_access_key(
    UserName='IAM_USER_NAME'
)

print(response['AccessKey'])
```

-   2、列出用户的访问密钥List a User's Access Keys
```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# List access keys through the pagination interface.
paginator = iam.get_paginator('list_access_keys')
for response in paginator.paginate(UserName='IAM_USER_NAME'):
    print(response)
```

-   3、获取最近使用的访问密钥

```py
import boto3


# Create IAM client
iam = boto3.client('iam')

# Get last use of access key
response = iam.get_access_key_last_used(
    AccessKeyId='ACCESS_KEY_ID'
)

print(response['AccessKeyLastUsed'])
```

-   4、更新访问密钥状态
> 将指定访问密钥的状态从“活动”改为“非活动”，反之依然。此操作可在按键旋转工作流程中用于禁用用户按键。

```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Update access key to be active
iam.update_access_key(
    AccessKeyId='ACCESS_KEY_ID',
    Status='Active',
    UserName='IAM_USER_NAME'
)
```

-   5、删除访问密钥

```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Delete access key
iam.delete_access_key(
    AccessKeyId='ACCESS_KEY_ID',
    UserName='IAM_USER_NAME'
)
```

####    使用IAM服务器证书
> 要在AWS上启用到您的网站或应用程序的HTTPS连接，您需要SSL / TLS服务器证书。要将您从外部提供商获得的证书与您的网站或AWS上的应用程序一起使用，您必须将该证书上载到IAM或将其导入到AWS Certificate Manager中。

-   1、列出你的服务器证书
列出存储在IAM中的服务器证书。如果不存在，该操作将返回一个空列表。

```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# List server certificates through the pagination interface
paginator = iam.get_paginator('list_server_certificates')
for response in paginator.paginate():
    print(response['ServerCertificateMetadataList'])
```
-   2、获取服务器证书

获取有关存储在IAM中的指定服务器证书的信息。

```py
import boto3


# Create IAM client
iam = boto3.client('iam')

# Get the server certificate
response = iam.get_server_certificate(ServerCertificateName='CERTIFICATE_NAME')
print(response['ServerCertificate'])
```

-   3、更新服务器证书

更新存储在IAM中的指定服务器证书的名称（和/或）路径。

```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Update the name of the server certificate
iam.update_server_certificate(
    ServerCertificateName='CERTIFICATE_NAME',
    NewServerCertificateName='NEW_CERTIFICATE_NAME'
)
```

-   4、删除服务器证书
```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Delete the server certificate
iam.delete_server_certificate(
    ServerCertificateName='CERTIFICATE_NAME'
)
```
####    管理IAM账户别名

如果您希望登录页面的URL包含公司名称或其他友好标识符而不是AWS账户ID，则可以为AWS账户ID创建别名。如果创建AWS账户别名，则登录页面URL会更改为包含该别名。

-   1、创建账户别名

```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Create an account alias
iam.create_account_alias(
    AccountAlias='ALIAS'
)
```
-   2、列出用户别名

```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# List account aliases through the pagination interface
paginator = iam.get_paginator('list_account_aliases')
for response in paginator.paginate():
    print(response['AccountAliases'])
```

-   3、删除用户别名

```py
import boto3

# Create IAM client
iam = boto3.client('iam')

# Delete an account alias
iam.delete_account_alias(
    AccountAlias='ALIAS'
)
```
### AWS Key Management Service
主密钥：CMK（客户主密钥），用于生成data key
数据密钥（data key）：用于加密文件，加密的data key存储在加密的文件中。

解密：先解密data key，再使用data key解密文件的其余部分。

这种使用主密钥和数据密钥的方式称为信封加密。



### S3示例（Simple Storage Service）
Amazon Simple Storage Service（Amazon S3）是一种对象存储服务，可提供可扩展性，数据可用性，安全性和性能。

####    S3 Bucket
> Amazon S3存储桶是用于保存文件的存储位置。S3文件称为对象。

-   1 创建S3存储桶（Bucket）
```py
import logging
import boto3
from botocore.exceptions import ClientError


def create_bucket(bucket_name, region=None):
    """Create an S3 bucket in a specified region

    If a region is not specified, the bucket is created in the S3 default
    region (us-east-1).

    :param bucket_name: Bucket to create
    :param region: String region to create bucket in, e.g., 'us-west-2'
    :return: True if bucket created, else False
    """

    # Create bucket
    try:
        if region is None:
            s3_client = boto3.client('s3')
            s3_client.create_bucket(Bucket=bucket_name)
        else:
            s3_client = boto3.client('s3', region_name=region)
            location = {'LocationConstraint': region}
            s3_client.create_bucket(Bucket=bucket_name,
                                    CreateBucketConfiguration=location)
    except ClientError as e:
        logging.error(e)
        return False
    return True
```
-   2 列出所有的Bucket
```py
# Retrieve the list of existing buckets
s3 = boto3.client('s3')
response = s3.list_buckets()

# Output the bucket names
print('Existing buckets:')
for bucket in response['Buckets']:
    print(f'  {bucket["Name"]}')
```



#### 上传文件

两种方法来将文件上传到S3存储桶。

-   1 upload_file:该方法通过将大文件分成较小的块并且并行上传每个块。
```py
import logging
import boto3
from botocore.exceptions import ClientError


def upload_file(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file
    s3_client = boto3.client('s3')
    try:
        response = s3_client.upload_file(file_name, bucket, object_name)
    except ClientError as e:
        logging.error(e)
        return False
    return True
```

-   2 upload_fileobj 方法接受可读类文件对象。必须以二进制模式而不是文本模式打开文件对象。
```py
s3 = boto3.client('s3')
with open("FILE_NAME", "rb") as f:
    s3.upload_fileobj(f, "BUCKET_NAME", "OBJECT_NAME")
```

-   3 The ExtraArgs Parameter(额外参数)

> 无论upload_file和upload_fileobj接受一个可选的ExtraArgs ，可用于各种用途的参数。

```py

#  设置指定要附加到S对象的元数据
s3.upload_file(
    'FILE_NAME', 'BUCKET_NAME', 'OBJECT_NAME',
    ExtraArgs={'Metadata': {'mykey': 'myvalue'}}
)

# ExtraArgs参数也可以用来设置自定义或多个ACL（访问控制列表）。
s3.upload_file(
    'FILE_NAME', 'BUCKET_NAME', 'OBJECT_NAME',
    ExtraArgs={
        'GrantRead': 'uri="http://acs.amazonaws.com/groups/global/AllUsers"',
        'GrantFullControl': 'id="01234567890abcdefg"',
    }
)
```

-   4 The Callback Parameter（回调参数）

> 无论upload_file和upload_fileobj接受一个可选的回调 参数。该参数引用Python SDK在传输操作期间间歇性调用的类。

调用Python类将执行该类的`__call__`方法。对于每次调用，传递给该类的字节数将一直传递到该点。此信息可用于实现进度监视器。

```py
s3.uploud_file(
    'FILE_NAME', 'BUCKET_NAME', 'OBJECT_NAME',
    Callback=ProgressPercentage('FILE_NAME')
)
```

ProcessPercentage类的示例实现

```py
import os
import sys
import threading

class ProgressPercentage(object):

    def __init__(self, filename):
        self._filename = filename
        self._size = float(os.path.getsize(filename))
        self._seen_so_far = 0
        self._lock = threading.Lock()

    def __call__(self, bytes_amount):
        # To simplify, assume this is hooked up to a single filename
        with self._lock:
            self._seen_so_far += bytes_amount
            percentage = (self._seen_so_far / self._size) * 100
            sys.stdout.write(
                "\r%s  %s / %s  (%.2f%%)" % (
                    self._filename, self._seen_so_far, self._size,
                    percentage))
            sys.stdout.flush()
```

####  下载文件

-   1 The `download_file` method accepts the names of the bucket and object to download and the filename to save the file to.
```py
import boto3

s3 = boto3.client('s3')
s3.download_file('BUCKET_NAME', 'OBJECT_NAME', 'FILE_NAME')
```


-   2 The `download_fileobj` method accepts a writeable file-like object. The file object must be opened in binary mode, not text mode.

-   3 与上传方法一样，下载方法也支持可选的 ExtraArgs和Callback参数。

#### 文件传输配置

-   1 分段传输
当文件大小超过multipart_threshold属性的值时，将发生分段传输 。
下面的示例将如果文件大小大于TransferConfig对象中指定的阈值，则将upload_file传输配置为多部分 。

```py
import boto3
from boto3.s3.transfer import TransferConfig

# Set the desired multipart threshold value (5GB)
GB = 1024 ** 3
config = TransferConfig(multipart_threshold=5*GB)

# Perform the transfer
s3 = boto3.client('s3')
s3.upload_file('FILE_NAME', 'BUCKET_NAME', 'OBJECT_NAME', Config=config)
```

-   2 并发传输操作
可以调整并发S3 API传输操作的最大数量，以调整连接速度。设置`max_concurrency`属性以增加或减少带宽使用量。

该属性的默认设置为10。通过减少带宽使用，减少该值。

```py
# To consume less downstream bandwidth, decrease the maximum concurrency
config = TransferConfig(max_concurrency=5)

# Download an S3 object
s3 = boto3.client('s3')
s3.download_file('BUCKET_NAME', 'OBJECT_NAME', 'FILE_NAME', Config=config)
```

-   3 线程
传输操作使用线程来实现并发。可以通过将use_threads属性设置为False来禁用线程使用。

如果禁用了线程使用，则不会发生传输并发。因此，将忽略max_concurrency属性的值。

```py
# Disable thread use/transfer concurrency
config = TransferConfig(use_threads=False)

s3 = boto3.client('s3')
s3.download_file('BUCKET_NAME', 'OBJECT_NAME', 'FILE_NAME', Config=config)
```

####   预签名URLs
没有AWS凭证或访问S3对象权限的用户可以使用预签名URL授予临时访问权限。

可以访问对象的AWS用户会生成一个预签名的URL。然后将生成的URL提供给未授权用户。可以在浏览器中输入或通过程序或HTML网页使用预签名的URL。预签名URL使用的凭证是生成URL的AWS用户的凭证。

预先签名的URL在生成URL时指定的有限时间内保持有效。
```py
import logging
import boto3
from botocore.exceptions import ClientError


def create_presigned_url(bucket_name, object_name, expiration=3600):
    """Generate a presigned URL to share an S3 object

    :param bucket_name: string
    :param object_name: string
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Presigned URL as string. If error, returns None.
    """

    # Generate a presigned URL for the S3 object
    s3_client = boto3.client('s3')
    try:
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': object_name},
                                                    ExpiresIn=expiration)
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL
    return response
```

用户可以通过在浏览器中输入预签名URL来下载S3对象。程序或HTML页面可以使用预签名的URL作为HTTP GET请求的一部分来下载S3对象。
```py
import requests    # To install: pip install requests

url = create_presigned_url('BUCKET_NAME', 'OBJECT_NAME')
if url is not None:
    response = requests.get(url)
```

-   1 使用预签名的URL执行其他S3操作

预签名URL的主要目的是授予用户对S3对象的临时访问权限。但是，可以使用预先签名的URL授予对S3存储桶和对象执行附加操作的权限。

```py
import logging
import boto3
from botocore.exceptions import ClientError


def create_presigned_url_expanded(client_method_name, method_parameters=None,
                                  expiration=3600, http_method=None):
    """Generate a presigned URL to invoke an S3.Client method

    Not all the client methods provided in the AWS Python SDK are supported.

    :param client_method_name: Name of the S3.Client method, e.g., 'list_buckets'
    :param method_parameters: Dictionary of parameters to send to the method
    :param expiration: Time in seconds for the presigned URL to remain valid
    :param http_method: HTTP method to use (GET, etc.)
    :return: Presigned URL as string. If error, returns None.
    """

    # Generate a presigned URL for the S3 client method
    s3_client = boto3.client('s3')
    try:
        response = s3_client.generate_presigned_url(ClientMethod=client_method_name,
                                                    Params=method_parameters,
                                                    ExpiresIn=expiration,
                                                    HttpMethod=http_method)
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL
    return response
```

-   2 生成一个预签名的URL来上传文件 

> 没有AWS凭证上传文件的用户可以使用预先签名的URL来执行上传。上载操作会发出HTTP POST请求，并要求将其他参数作为请求的一部分发送。

```py
import logging
import boto3
from botocore.exceptions import ClientError


def create_presigned_post(bucket_name, object_name,
                          fields=None, conditions=None, expiration=3600):
    """Generate a presigned URL S3 POST request to upload a file

    :param bucket_name: string
    :param object_name: string
    :param fields: Dictionary of prefilled form fields
    :param conditions: List of conditions to include in the policy
    :param expiration: Time in seconds for the presigned URL to remain valid
    :return: Dictionary with the following keys:
        url: URL to post to
        fields: Dictionary of form fields and values to submit with the POST
    :return: None if error.
    """

    # Generate a presigned S3 POST URL
    s3_client = boto3.client('s3')
    try:
        response = s3_client.generate_presigned_post(bucket_name,
                                                     object_name,
                                                     Fields=fields,
                                                     Conditions=conditions,
                                                     ExpiresIn=expiration)
    except ClientError as e:
        logging.error(e)
        return None

    # The response contains the presigned URL and required fields
    return response
```

生成的预签名URL包括URL和必须作为后续HTTP POST请求的一部分传递的其他字段。

以下代码演示了如何将请求包与预签名的POST URL 一起使用，以执行POST请求以将文件上传到S3。

```py
import requests    # To install: pip install requests

# Generate a presigned S3 POST URL
object_name = 'OBJECT_NAME'
response = create_presigned_post('BUCKET_NAME', object_name)
if response is None:
    exit(1)

# Demonstrate how another Python program can use the presigned URL to upload a file
with open(object_name, 'rb') as f:
    files = {'file': (object_name, f)}
    http_response = requests.post(response['url'], data=response['fields'], files=files)
# If successful, returns HTTP status code 204
logging.info(f'File upload HTTP status code: {http_response.status_code}')
```

预签名的POST URL和字段值也可以在HTML页面中使用。

####    桶策略（Bucket Policy）

S3存储桶可以具有可选策略，该策略向其他AWS账户或AWS Identity and Access Management（IAM）用户授予访问权限。存储桶策略使用与基于资源的IAM策略相同的JSON格式定义。

-   1 检索桶策略
```py
import boto3

# Retrieve the policy of the specified bucket
s3 = boto3.client('s3')
result = s3.get_bucket_policy(Bucket='BUCKET_NAME')
print(result['Policy'])
```

-   2 设置桶策略
可以通过调用`put_bucket_policy`方法来设置存储桶的策略。
```py
import json

# Create a bucket policy
bucket_name = 'BUCKET_NAME'
bucket_policy = {
    'Version': '2012-10-17',
    'Statement': [{
        'Sid': 'AddPerm',
        'Effect': 'Allow',
        'Principal': '*',
        'Action': ['s3:GetObject'],
        'Resource': f'arn:aws:s3:::{bucket_name}/*'
    }]
}

# Convert the policy from JSON dict to string
bucket_policy = json.dumps(bucket_policy)

# Set the new policy
s3 = boto3.client('s3')
s3.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)
```


-   3 删除桶策略
```py
# Delete a bucket's policy
s3 = boto3.client('s3')
s3.delete_bucket_policy(Bucket='BUCKET_NAME')
```

####    访问权限

-   获取桶的访问控制列表
```py
import boto3

s3 = boto3.client('s3')
result = s3.get_bucket_acl(Bucket='my-bucket')
print(result)
```


####    使用S3存储桶作为一个静态的web主机

> 可以将S3存储桶配置为托管静态网站。


-   1 检索网站配置
`get_bucket_website`方法来检索存储桶的网站配置 。
```py
import boto3

# Retrieve the website configuration
s3 = boto3.client('s3')
result = s3.get_bucket_website(Bucket='BUCKET_NAME')
```

-   2 设置网站配置
可以通过调用`put_bucket_website`方法来设置存储桶的网站配置 。

```py
# Define the website configuration
website_configuration = {
    'ErrorDocument': {'Key': 'error.html'},
    'IndexDocument': {'Suffix': 'index.html'},
}

# Set the website configuration
s3 = boto3.client('s3')
s3.put_bucket_website(Bucket='BUCKET_NAME',
                      WebsiteConfiguration=website_configuration)
```

-   3 删除网站配置
```py
# Delete the website configuration
s3 = boto3.client('s3')
s3.delete_bucket_website(Bucket='BUCKET_NAME')

```

####    桶跨源资源共享配置（CORS）

> 跨源资源共享（CORS）使一个域中的客户端Web应用程序可以访问另一个域中的资源。可以将S3存储桶配置为启用跨域请求。该配置定义了规则，这些规则指定了允许的来源，HTTP方法（GET，PUT等）以及其他元素。


-   1 检索桶CORS配置
`get_bucket_cors` method

```py
import logging
import boto3
from botocore.exceptions import ClientError


def get_bucket_cors(bucket_name):
    """Retrieve the CORS configuration rules of an Amazon S3 bucket

    :param bucket_name: string
    :return: List of the bucket's CORS configuration rules. If no CORS
    configuration exists, return empty list. If error, return None.
    """

    # Retrieve the CORS configuration
    s3 = boto3.client('s3')
    try:
        response = s3.get_bucket_cors(Bucket=bucket_name)
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchCORSConfiguration':
            return []
        else:
            # AllAccessDisabled error == bucket not found
            logging.error(e)
            return None
    return response['CORSRules']
```

-   2 设置存储桶CORS配置
`put_bucket_cors` method

```py
＃定义配置规则
cors_configuration  =  { 
    'CORSRules' ： [{ 
        'AllowedHeaders' ： [ 'Authorization' ]，
        'AllowedMethods' ： [ 'GET' ， 'PUT' ]，
        'AllowedOrigins' ： [ '*' ]，
        'ExposeHeaders ' ： [ 'GET' ， 'PUT' ]，
        'MaxAgeSeconds' ： 3000 
    }] 
}

＃设置CORS配置
s3  =  boto3 。客户（'s3' ）
s3 。put_bucket_cors （Bucket = 'BUCKET_NAME' ，
                   CORSConfiguration = cors_configuration ）
```

####    AWS Secrets Manager

> 该代码使用适用于Python的AWS开发工具包检索解密的密钥值。

-   检索密钥值`get_secret_value.
`

```py
import boto3
from botocore.exceptions import ClientError


def get_secret():
    secret_name = "MySecretName"
    region_name = "us-west-2"

    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            text_secret_data = get_secret_value_response['SecretString']
        else:
            binary_secret_data = get_secret_value_response['SecretBinary']

        # Your code goes here.
```


### SES示例(simple email service)
> Amazon Simple Email Service（SES）是一个电子邮件平台，为您提供了一种简单，经济高效的方式，使您可以使用自己的电子邮件地址和域发送和接收电子邮件。




### SQS示例（Simple Queue Service）

####    在SQS中使用队列
-   1 列出你的Queues
```py
import boto3

# Create SQS client
sqs = boto3.client('sqs')

# List SQS queues
response = sqs.list_queues()

print(response['QueueUrls'])
```

-   2 创建队列
```py
import boto3

# Create SQS client
sqs = boto3.client('sqs')

# Create a SQS queue
response = sqs.create_queue(
    QueueName='SQS_QUEUE_NAME',
    Attributes={
        'DelaySeconds': '60',
        'MessageRetentionPeriod': '86400'
    }
)

print(response['QueueUrl'])
```

-   3 获取队列的URL
```py
import boto3

# Create SQS client
sqs = boto3.client('sqs')

# Get URL for SQS queue
response = sqs.get_queue_url(QueueName='SQS_QUEUE_NAME')

print(response['QueueUrl'])
```

-   4 删除队列

```py
import boto3

# Create SQS client
sqs = boto3.client('sqs')

# Delete SQS queue
sqs.delete_queue(QueueUrl='SQS_QUEUE_URL')
```

####    在sqs中发送和接收消息

-   1 发送消息到队列
```py
import boto3

# Create SQS client
sqs = boto3.client('sqs')

queue_url = 'SQS_QUEUE_URL'

# Send message to SQS queue
response = sqs.send_message(
    QueueUrl=queue_url,
    DelaySeconds=10,
    MessageAttributes={
        'Title': {
            'DataType': 'String',
            'StringValue': 'The Whistler'
        },
        'Author': {
            'DataType': 'String',
            'StringValue': 'John Grisham'
        },
        'WeeksOn': {
            'DataType': 'Number',
            'StringValue': '6'
        }
    },
    MessageBody=(
        'Information about current NY Times fiction bestseller for '
        'week of 12/11/2016.'
    )
)

print(response['MessageId'])
```

-   2 从一个队列接收和删除消息
```py
import boto3

# Create SQS client
sqs = boto3.client('sqs')

queue_url = 'SQS_QUEUE_URL'

# Receive message from SQS queue
response = sqs.receive_message(
    QueueUrl=queue_url,
    AttributeNames=[
        'SentTimestamp'
    ],
    MaxNumberOfMessages=1,
    MessageAttributeNames=[
        'All'
    ],
    VisibilityTimeout=0,
    WaitTimeSeconds=0
)

message = response['Messages'][0]
receipt_handle = message['ReceiptHandle']

# Delete received message from queue
sqs.delete_message(
    QueueUrl=queue_url,
    ReceiptHandle=receipt_handle
)
print('Received and deleted message: %s' % message)

```

####    在SQS中管理可见性超时

> 展示了如何指定不可见队列接收消息的时间间隔。

-   更改可见性超时

```py
import boto3

# Create SQS client
sqs = boto3.client('sqs')

queue_url = 'SQS_QUEUE_URL'

# Receive message from SQS queue
response = sqs.receive_message(
    QueueUrl=queue_url,
    AttributeNames=[
        'SentTimestamp'
    ],
    MaxNumberOfMessages=1,
    MessageAttributeNames=[
        'All'
    ],
)

message = response['Messages'][0]
receipt_handle = message['ReceiptHandle']

# Change visibility timeout of message from queue
sqs.change_message_visibility(
    QueueUrl=queue_url,
    ReceiptHandle=receipt_handle,
    VisibilityTimeout=20
)
print('Received and changed visibility timeout of message: %s' % message)
```

####    在SQS中启用长轮询

> 长轮询通过允许 SQS 在发送响应之前等待指定时间以使消息在队列中可用，从而减少了空响应的数量。同样，长时间轮询通过查询所有服务器而不是对服务器进行采样，消除了虚假的空响应。要启用长时间轮询，必须为收到的消息指定非零等待时间。


-   1 创建队列时启用长轮询
```py
import boto3

# Create SQS client
sqs = boto3.client('sqs')

# Create a SQS queue with long polling enabled
response = sqs.create_queue(
    QueueName='SQS_QUEUE_NAME',
    Attributes={'ReceiveMessageWaitTimeSeconds': '20'}
)

print(response['QueueUrl'])
```

-   2 在现有的队列上启用长轮询
```py
import boto3

# Create SQS client
sqs = boto3.client('sqs')

queue_url = 'SQS_QUEUE_URL'

# Enable long polling on an existing SQS queue
sqs.set_queue_attributes(
    QueueUrl=queue_url,
    Attributes={'ReceiveMessageWaitTimeSeconds': '20'}
)
```

-   3 在消息接收上启用长轮询
```py
import boto3

# Create SQS client
sqs = boto3.client('sqs')

queue_url = 'SQS_QUEUE_URL'

# Long poll for message on provided SQS queue
response = sqs.receive_message(
    QueueUrl=queue_url,
    AttributeNames=[
        'SentTimestamp'
    ],
    MaxNumberOfMessages=1,
    MessageAttributeNames=[
        'All'
    ],
    WaitTimeSeconds=20
)

print(response)
```
####    在SQS中使用死信队列

> 用于接收和保留其他队列无法处理的消息

> 死信队列是其他（源）队列可以针对无法成功处理的消息的目标。您可以搁置这些消息并将它们隔离在死信队列中，以确定为什么无法成功处理它们。您必须分别配置将消息发送到死信队列的每个源队列。多个队列可以针对单个死信队列。



-   将sqs中的消息路由到死信队列

在创建充当死信队列的队列之后，必须配置将未处理的消息路由到死信队列的普通队列。为此，请指定一个重新驱动策略，该策略 标识要用作死信队列的队列 以及 在将单个消息路由到死信队列之前各个消息的最大接收数。

```py
import json

import boto3

# Create SQS client
sqs = boto3.client('sqs')

queue_url = 'SOURCE_QUEUE_URL'
dead_letter_queue_arn = 'DEAD_LETTER_QUEUE_ARN'

redrive_policy = {
    'deadLetterTargetArn': dead_letter_queue_arn,
    'maxReceiveCount': '10'
}


# Configure queue to send messages to dead letter queue
sqs.set_queue_attributes(
    QueueUrl=queue_url,
    Attributes={
        'RedrivePolicy': json.dumps(redrive_policy)
    }
)
```



