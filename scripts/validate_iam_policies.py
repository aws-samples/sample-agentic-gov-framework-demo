#!/usr/bin/env python3
"""
Validate every IAM policy document in the synthesized CDK templates with IAM
Access Analyzer (ValidatePolicy), before CloudFormation sees them.

CloudFormation only rejects a bad policy mid-deploy ("Policy has invalid
action") and rolls the stack back. This synthesizes both stacks for each
context variant, extracts every policy document (role trust and inline
policies, managed policies, bucket, key, queue, log and secret resource
policies, and one resource-policy statement per AWS::Lambda::Permission),
resolves intrinsics to placeholder ARNs in account 123456789012, and calls
access-analyzer:ValidatePolicy, which is read-only.

Exit 1 on any ERROR, on any SECURITY_WARNING not reviewed in ACKNOWLEDGED, on
a policy shape this script does not know how to extract, or on an intrinsic it
cannot resolve. WARNING and SUGGESTION findings are reported but do not fail.

Usage:
    python scripts/validate_iam_policies.py [--profile P] [--region R] [--report out.json]
Needs credentials allowed access-analyzer:ValidatePolicy. Nothing is deployed.
"""
import argparse
import json
import os
import subprocess  # nosec B404 -- static argv below, no shell
import sys
import tempfile
import uuid

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDK_DIR = os.path.join(PROJECT_ROOT, "cdk")
STACKS = ("FsiComplianceData", "FsiComplianceAgents")
ACCOUNT, REGION, PARTITION = "123456789012", "us-east-1", "aws"
FAIL_TYPES = ("ERROR", "SECURITY_WARNING")
# Reviewed SECURITY_WARNINGs that are not genuine: (issueCode, logical-id prefix) -> reason.
# Never acknowledge an ERROR; CloudFormation or IAM may reject it.
ACKNOWLEDGED = {
    ("DYNAMODB_ATTRIBUTES_WITHOUT_RETURN_VALUES", "ExecutorAgentRoleDefaultPolicy"):
        "executor UpdateItem on compliance-decisions: the role already reads the whole item via "
        "GetItem, so ReturnValues exposes nothing new; the handler never passes ReturnValues "
        "(cdk/agents_stack.py executor UpdateItem comment, tests/test_executor_partial_failure_retry.py)",
}

# Every optional CDK context key the stacks read (cdk/README.md), on top of cdk/cdk.json.
VARIANTS = {
    "default": {},
    "full-context": {
        "allow_console_drift_injection": "true",
        "console_host_role_arn": f"arn:aws:iam::{ACCOUNT}:role/console-host",
        "ci_role_arn": f"arn:aws:iam::{ACCOUNT}:role/ci",
        "alarm_email": "oncall@example.com",
    },
    "pan-concurrency-unset": {"pan_filter_reserved_concurrency": "0"},
    "retention-365": {"audit_archive_retention_days": 365},
}

_SYNTH_SCRIPT = """
import json, sys
from aws_cdk import App
from agents_stack import AgentsStack
from data_stack import DataStack
app = App(context=json.loads(sys.argv[1]), outdir=sys.argv[2])
data = DataStack(app, "FsiComplianceData")
AgentsStack(app, "FsiComplianceAgents", data_stack=data)
app.synth()
"""


class Unresolvable(Exception):
    """An intrinsic or policy shape this script does not handle (fails the run)."""


def synth(context: dict) -> dict:
    """{stack name: template} for one context variant (cdk.json context merged in)."""
    with open(os.path.join(CDK_DIR, "cdk.json"), encoding="utf-8") as f:
        merged = dict(json.load(f).get("context", {}), **context)
    with tempfile.TemporaryDirectory(prefix="iam-validate-") as outdir:
        result = subprocess.run(  # nosec B603 # nosemgrep -- static argv (this interpreter + fixed inline synth script), list form, no shell, only cdk.json context as data
            [sys.executable, "-c", _SYNTH_SCRIPT, json.dumps(merged), outdir],
            cwd=CDK_DIR, capture_output=True, text=True, timeout=300, check=False)
        if result.returncode != 0:
            raise SystemExit(f"synth failed for context {context}:\n{result.stderr[-4000:]}")
        templates = {}
        for name in STACKS:
            with open(os.path.join(outdir, f"{name}.template.json"), encoding="utf-8") as f:
                templates[name] = json.load(f)
        return templates


class Resolver:
    """Renders CloudFormation intrinsics to plausible literal values."""

    _NAME_PROPS = ("TableName", "BucketName", "RoleName", "FunctionName", "QueueName",
                   "ManagedPolicyName", "LogGroupName", "AlarmName", "TopicName", "Name", "AliasName")

    def __init__(self, templates: dict):
        self.resources = {}
        self.exports = {}
        for stack, tpl in templates.items():
            for lid, res in tpl.get("Resources", {}).items():
                self.resources[(stack, lid)] = res
            for out in tpl.get("Outputs", {}).values():
                name = (out.get("Export") or {}).get("Name")
                if isinstance(name, str):
                    self.exports[name] = (stack, out["Value"])

    def _res(self, stack, lid):
        try:
            return self.resources[(stack, lid)]
        except KeyError:
            raise Unresolvable(f"{stack}: no resource {lid}") from None

    def _name(self, stack, lid):
        props = self._res(stack, lid).get("Properties", {})
        for key in self._NAME_PROPS:
            if isinstance(props.get(key), str):
                return props[key]
        name = lid.lower() if self._res(stack, lid)["Type"] == "AWS::S3::Bucket" else lid
        return name[:63]

    def _key_id(self, stack, lid):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{stack}/{lid}"))

    def ref(self, stack, target):
        pseudo = {"AWS::AccountId": ACCOUNT, "AWS::Region": REGION, "AWS::Partition": PARTITION,
                  "AWS::URLSuffix": "amazonaws.com", "AWS::StackName": stack}
        if target in pseudo:
            return pseudo[target]
        rtype = self._res(stack, target)["Type"]
        name = self._name(stack, target)
        return {
            "AWS::DynamoDB::Table": name,
            "AWS::S3::Bucket": name,
            "AWS::SQS::Queue": f"https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/{name}",
            "AWS::IAM::Role": name,
            "AWS::IAM::ManagedPolicy": f"arn:{PARTITION}:iam::{ACCOUNT}:policy/{name}",
            "AWS::Lambda::Function": name,
            "AWS::SecretsManager::Secret":
                f"arn:{PARTITION}:secretsmanager:{REGION}:{ACCOUNT}:secret:{name}-AbCdEf",
            "AWS::KMS::Key": self._key_id(stack, target),
            "AWS::Logs::LogGroup": name,
            "AWS::SNS::Topic": f"arn:{PARTITION}:sns:{REGION}:{ACCOUNT}:{name}",
        }.get(rtype) or self._unknown(stack, target, "Ref")

    def get_att(self, stack, lid, attr):
        rtype = self._res(stack, lid)["Type"]
        name = self._name(stack, lid)
        arn = {
            "AWS::DynamoDB::Table": f"arn:{PARTITION}:dynamodb:{REGION}:{ACCOUNT}:table/{name}",
            "AWS::S3::Bucket": f"arn:{PARTITION}:s3:::{name}",
            "AWS::SQS::Queue": f"arn:{PARTITION}:sqs:{REGION}:{ACCOUNT}:{name}",
            "AWS::IAM::Role": f"arn:{PARTITION}:iam::{ACCOUNT}:role/{name}",
            "AWS::Lambda::Function": f"arn:{PARTITION}:lambda:{REGION}:{ACCOUNT}:function:{name}",
            "AWS::KMS::Key": f"arn:{PARTITION}:kms:{REGION}:{ACCOUNT}:key/{self._key_id(stack, lid)}",
            "AWS::Events::Rule": f"arn:{PARTITION}:events:{REGION}:{ACCOUNT}:rule/{name}",
            "AWS::CloudWatch::Alarm": f"arn:{PARTITION}:cloudwatch:{REGION}:{ACCOUNT}:alarm:{name}",
            "AWS::Logs::LogGroup": f"arn:{PARTITION}:logs:{REGION}:{ACCOUNT}:log-group:{name}:*",
            "AWS::Bedrock::Guardrail": f"arn:{PARTITION}:bedrock:{REGION}:{ACCOUNT}:guardrail/a1b2c3d4e5f6",
        }.get(rtype)
        if attr == "Arn" and arn:
            return arn
        if (rtype, attr) == ("AWS::DynamoDB::Table", "StreamArn"):
            return f"{arn}/stream/2026-01-01T00:00:00.000"
        if (rtype, attr) == ("AWS::SQS::Queue", "QueueName"):
            return name
        if (rtype, attr) == ("AWS::Bedrock::Guardrail", "GuardrailArn"):
            return arn
        if (rtype, attr) == ("AWS::Bedrock::Guardrail", "GuardrailId"):
            return "a1b2c3d4e5f6"
        return self._unknown(stack, lid, f"GetAtt {attr}")

    def _unknown(self, stack, lid, what):
        raise Unresolvable(f"{stack}: cannot resolve {what} of {lid} "
                           f"({self._res(stack, lid)['Type']}); extend Resolver")

    def render(self, stack, value):
        if isinstance(value, list):
            return [self.render(stack, v) for v in value]
        if not isinstance(value, dict):
            return value
        if len(value) == 1:
            (key, arg), = value.items()
            if key == "Ref":
                return self.ref(stack, arg)
            if key == "Fn::GetAtt":
                lid, attr = arg if isinstance(arg, list) else arg.split(".", 1)
                return self.get_att(stack, lid, attr)
            if key == "Fn::Join":
                sep, parts = arg
                return sep.join(str(self.render(stack, p)) for p in parts)
            if key == "Fn::Sub":
                text, variables = (arg, {}) if isinstance(arg, str) else arg
                for var, val in variables.items():
                    text = text.replace("${" + var + "}", str(self.render(stack, val)))
                for pseudo in ("AWS::AccountId", "AWS::Region", "AWS::Partition", "AWS::URLSuffix"):
                    text = text.replace("${" + pseudo + "}", self.ref(stack, pseudo))
                if "${" in text:
                    raise Unresolvable(f"{stack}: unresolved Fn::Sub {text}")
                return text
            if key == "Fn::ImportValue":
                if arg not in self.exports:
                    raise Unresolvable(f"{stack}: no export {arg}")
                src_stack, src_value = self.exports[arg]
                return self.render(src_stack, src_value)
            if key.startswith("Fn::"):
                raise Unresolvable(f"{stack}: unsupported intrinsic {key}")
        return {k: self.render(stack, v) for k, v in value.items()}


S3_BUCKET = "AWS::S3::Bucket"
ASSUME_ROLE = "AWS::IAM::AssumeRolePolicyDocument"
# resource type -> [(property path, policy type, validate-policy resource type)]
POLICY_PROPERTIES = {
    "AWS::IAM::Policy": [("PolicyDocument", "IDENTITY_POLICY", None)],
    "AWS::IAM::ManagedPolicy": [("PolicyDocument", "IDENTITY_POLICY", None)],
    "AWS::IAM::Role": [("AssumeRolePolicyDocument", "RESOURCE_POLICY", ASSUME_ROLE),
                       ("Policies[].PolicyDocument", "IDENTITY_POLICY", None)],
    "AWS::IAM::User": [("Policies[].PolicyDocument", "IDENTITY_POLICY", None)],
    "AWS::IAM::Group": [("Policies[].PolicyDocument", "IDENTITY_POLICY", None)],
    "AWS::S3::BucketPolicy": [("PolicyDocument", "RESOURCE_POLICY", S3_BUCKET)],
    "AWS::KMS::Key": [("KeyPolicy", "RESOURCE_POLICY", None)],
    "AWS::SQS::QueuePolicy": [("PolicyDocument", "RESOURCE_POLICY", None)],
    "AWS::SNS::TopicPolicy": [("PolicyDocument", "RESOURCE_POLICY", None)],
    "AWS::Logs::ResourcePolicy": [("PolicyDocument", "RESOURCE_POLICY", None)],
    "AWS::SecretsManager::ResourcePolicy": [("ResourcePolicy", "RESOURCE_POLICY", None)],
    "AWS::DynamoDB::Table": [("ResourcePolicy.PolicyDocument", "RESOURCE_POLICY", "AWS::DynamoDB::Table")],
}


def _at(props, path):
    """Yield (path, value) for a dotted path where `x[]` iterates a list."""
    head, _, rest = path.partition(".")
    if head.endswith("[]"):
        for i, item in enumerate(props.get(head[:-2]) or []):
            for sub_path, value in _at(item, rest):
                yield f"{head[:-2]}[{i}].{sub_path}", value
    elif head in props:
        if rest:
            yield from ((f"{head}.{p}", v) for p, v in _at(props[head] or {}, rest))
        else:
            yield head, props[head]


def _contains_policy(value) -> bool:
    if isinstance(value, dict):
        return "Statement" in value or any(_contains_policy(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_policy(v) for v in value)
    return isinstance(value, str) and '"Statement"' in value


def _lambda_permission_policy(resolver, stack, props):
    """The statement Lambda adds to the function policy for one AWS::Lambda::Permission."""
    principal = resolver.render(stack, props["Principal"])
    function = resolver.render(stack, props["FunctionName"])
    if not function.startswith("arn:"):
        function = f"arn:{PARTITION}:lambda:{REGION}:{ACCOUNT}:function:{function}"
    statement = {
        "Effect": "Allow",
        "Principal": {"Service": principal} if principal.endswith(".amazonaws.com") else {"AWS": principal},
        "Action": props["Action"],
        "Resource": function,
    }
    condition = {}
    if "SourceArn" in props:
        condition["ArnLike"] = {"aws:SourceArn": resolver.render(stack, props["SourceArn"])}
    if "SourceAccount" in props:
        condition["StringEquals"] = {"aws:SourceAccount": resolver.render(stack, props["SourceAccount"])}
    if condition:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


def extract_policies(templates: dict):
    """[(stack, logical id, type, property path, policy type, resource type, document)]."""
    resolver = Resolver(templates)
    found = []
    for stack, tpl in templates.items():
        for lid, res in tpl.get("Resources", {}).items():
            rtype, props = res["Type"], res.get("Properties", {})
            handled = set()
            if rtype == "AWS::Lambda::Permission":
                found.append((stack, lid, rtype, "(permission statement)", "RESOURCE_POLICY", None,
                              _lambda_permission_policy(resolver, stack, props)))
                continue
            for path, policy_type, resource_type in POLICY_PROPERTIES.get(rtype, []):
                for full_path, raw in _at(props, path):
                    doc = resolver.render(stack, raw)
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    found.append((stack, lid, rtype, full_path, policy_type, resource_type, doc))
                    handled.add(full_path.split(".")[0].split("[")[0])
            leftover = {k: v for k, v in props.items() if k not in handled}
            if _contains_policy(leftover):
                raise Unresolvable(f"{stack}/{lid} ({rtype}) carries a policy document this script "
                                   f"does not extract; add it to POLICY_PROPERTIES")
    return found


def validate(client, policy_type, resource_type, document):
    kwargs = {"policyType": policy_type, "policyDocument": json.dumps(document)}
    if resource_type:
        kwargs["validatePolicyResourceType"] = resource_type
    findings = []
    for page in client.get_paginator("validate_policy").paginate(**kwargs):
        findings.extend(page["findings"])
    return [{"findingType": f["findingType"], "issueCode": f["issueCode"],
             "findingDetails": f["findingDetails"],
             "locations": [loc.get("path") for loc in f.get("locations", [])]} for f in findings]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--profile", default=os.environ.get("AWS_PROFILE"))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", REGION))
    parser.add_argument("--report", help="write the full JSON report here")
    args = parser.parse_args(argv)

    import boto3  # deferred so --help works without AWS dependencies
    client = boto3.Session(profile_name=args.profile, region_name=args.region).client("accessanalyzer")

    cache, report, totals, failed = {}, [], {}, False
    for variant, context in VARIANTS.items():
        try:
            policies = extract_policies(synth(context))
        except Unresolvable as e:
            print(f"[{variant}] FAIL: {e}")
            return 1
        for stack, lid, rtype, path, policy_type, resource_type, doc in policies:
            key = (policy_type, resource_type, json.dumps(doc, sort_keys=True))
            if key not in cache:
                cache[key] = validate(client, policy_type, resource_type, doc)
            findings = cache[key]
            for f in findings:
                totals[f["findingType"]] = totals.get(f["findingType"], 0) + 1
                ack = f["findingType"] == "SECURITY_WARNING" and next(
                    (why for (code, prefix), why in ACKNOWLEDGED.items()
                     if code == f["issueCode"] and lid.startswith(prefix)), None)
                marker = "ack" if ack else "FAIL" if f["findingType"] in FAIL_TYPES else "note"
                failed |= marker == "FAIL"
                print(f"[{variant}] {marker} {f['findingType']} {f['issueCode']} "
                      f"{stack}/{lid}.{path} {f['locations']}: {f['findingDetails']}"
                      + (f" -- acknowledged: {ack}" if ack else ""))
            report.append({"variant": variant, "stack": stack, "logicalId": lid, "resourceType": rtype,
                           "property": path, "policyType": policy_type,
                           "validatePolicyResourceType": resource_type, "findings": findings})
        print(f"[{variant}] validated {len(policies)} policy documents")

    print(f"{len(report)} validations ({len(cache)} distinct documents) across {len(VARIANTS)} "
          f"variants; findings by type: {totals or 'none'}")
    if args.report:
        os.makedirs(os.path.dirname(os.path.abspath(args.report)), exist_ok=True)
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump({"totals": totals, "policies": report}, f, indent=2)
    if failed:
        print(f"IAM POLICY VALIDATION: FAIL ({'/'.join(FAIL_TYPES)} findings above)")
        return 1
    print("IAM POLICY VALIDATION: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
