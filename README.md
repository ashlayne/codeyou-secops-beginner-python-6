# 🧩 Python Assignment: Incident Triage Tracker (with Simple Classes)

## Why we’re doing this

Security teams don’t just “look at alerts” — they **track** them: what happened, what evidence exists, how serious it is, and what action was taken. This assignment builds a tiny version of that workflow in Python.

You will write a program that reads a small set of alerts, converts them into `Alert` objects, classifies them, and writes a summary report.

---

## Learning Objectives

By completing this assignment, you will be able to:

* Use **loops and conditionals** to process security-style data
* Store and work with data using **lists**
* Read from and write to **files**
* Create and use a **simple class** with attributes and methods
* Produce a clean **summary report** like a SOC might generate

---

# ✅ Provided Input File: `alerts.txt`

Create a text file named `alerts.txt` in the same folder as your Python script:

```text
2026-01-03,login_failure,bob,8.8.8.8
2026-01-03,login_success,alice,192.168.1.25
2026-01-03,file_hash_detected,workstation-7,275a021bbfb6483e2f3b2ed34a59dcdf57f7e3c2efb8fe2bc5e756e508d2f5a9
2026-01-03,dns_query,finance-laptop,ms-secure-login.net
2026-01-03,port_scan,web-server-1,185.220.101.6
```

---

# Part 1 — Walkthrough (Guided Build)

## Step 1: Read and Parse the File

Create `incident_tracker.py` and start by reading the file:

```python
with open("alerts.txt", "r", encoding="utf-8") as f:
    lines = f.read().splitlines()

print(f"Loaded {len(lines)} alerts.")
```

Parse each line into parts:

```python
records = []
for line in lines:
    date, alert_type, asset, indicator = line.split(",")
    records.append((date, alert_type, asset, indicator))

print(records[0])
```

✅ Checkpoint: you should see the first tuple printed correctly.

---

## Step 2: Create a Simple Class

Now we turn each record into an object.

```python
class Alert:
    def __init__(self, date, alert_type, asset, indicator):
        self.date = date
        self.alert_type = alert_type
        self.asset = asset
        self.indicator = indicator
```

✅ Checkpoint: No errors when you run it.

---

## Step 3: Add a Method to Classify Severity

Add a method that returns a severity string:

```python
class Alert:
    def __init__(self, date, alert_type, asset, indicator):
        self.date = date
        self.alert_type = alert_type
        self.asset = asset
        self.indicator = indicator

    def severity(self):
        if self.alert_type == "file_hash_detected":
            return "HIGH"
        elif self.alert_type in ["port_scan", "dns_query"]:
            return "MEDIUM"
        else:
            return "LOW"
```

✅ Checkpoint: You can call `some_alert.severity()` and get HIGH/MEDIUM/LOW.

---

## Step 4: Convert Records into Alert Objects

Loop through `records` and create a list of `Alert` objects:

```python
alerts = []
for date, alert_type, asset, indicator in records:
    alerts.append(Alert(date, alert_type, asset, indicator))

print(alerts[0].alert_type, alerts[0].severity())
```

✅ Checkpoint: Prints the first alert type and its severity.

---

## Step 5: Print a Summary Report

Count how many are HIGH/MEDIUM/LOW:

```python
high = 0
medium = 0
low = 0

for a in alerts:
    sev = a.severity()
    if sev == "HIGH":
        high += 1
    elif sev == "MEDIUM":
        medium += 1
    else:
        low += 1

print("\n=== Summary ===")
print(f"HIGH: {high}")
print(f"MEDIUM: {medium}")
print(f"LOW: {low}")
```

---
## Step 5: Replace 'magic strings' with Enum values
### Why We’re Adding This Step

So far, alert types like:
```
login_failure
dns_query
file_hash_detected
port_scan
...
```

are represented as plain strings. This works — but it’s fragile:

- Typos cause bugs
- No central list of valid alert types
- Hard to refactor or extend later when new alert types are discovered/added

In real security tools, these values are often stored as constants or enums to make code safer and clearer.

### 1️⃣ Import Enum Support
At the top of your file add this so we can use `Enum`:
```py
from enum import Enum
```

### 2️⃣ Define the Enum

Add this somewhere above your `Alert` class:
```py
class AlertType(Enum):
    LOGIN_FAILURE = "login_failure"
    LOGIN_SUCCESS = "login_success"
    FILE_HASH_DETECTED = "file_hash_detected"
    DNS_QUERY = "dns_query"
    PORT_SCAN = "port_scan"
```
This `AlertType` class is "inheriting" all the characteristics of `Enum`.

#### 🧠 Note:

The left side is the Python-friendly name

The right side matches exactly what appears in alerts.txt

### 3️⃣ Convert Strings into Enum Values

When parsing the file, instead of storing the alert type as a raw string, convert it by doing as below:
```py
records = []
for line in lines:
    date, alert_type_str, asset, indicator = line.split(",")

    alert_type = AlertType(alert_type_str)
    records.append((date, alert_type, asset, indicator))
```

📌 If the string doesn’t match one of the enum values, Python will raise an error — this is good. It protects you from bad data.

### 4️⃣ Update the Alert Class to Use the Enum

Modify the constructor:
```py
class Alert:
    def __init__(self, date, alert_type, asset, indicator):
        self.date = date
        self.alert_type = alert_type  # now an AlertType
        self.asset = asset
        self.indicator = indicator
```

### 5️⃣ Update Severity Logic to Use Enum Members

Replace string comparisons with enum comparisons:
```py
def severity(self):
    if self.alert_type == AlertType.FILE_HASH_DETECTED:
        return "HIGH"
    elif self.alert_type in [AlertType.PORT_SCAN, AlertType.DNS_QUERY]:
        return "MEDIUM"
    else:
        return "LOW"
```

This is cleaner, safer, and more readable.

#### 🧠 Note:
It may be tempting to make `"HIGH"`, `"MEDIUM"`, `"LOW"` into an `Enum` as well. This is perfectly acceptable although there is little-to-no benefit in this case since WE are determining the string value in code and only in one place without impacting successful execution, e.g. it's only being defined/used in this one method `severity()`.  
**Rule of thumb**: If the string is **used for comparisons**, or will be **used or defined in multiple places**, or the string will otherwise **impact/necessitate successful execution of the script** then it's best practice to use an `Enum` instead of a string.


### 6️⃣ (Optional) Improve str Output

If you added `__str__`, update it slightly:
```py
def __str__(self):
    return (
        f"{self.date} [{self.severity()}]"
        f"{self.alert_type.value} on {self.asset} -> {self.indicator}"
    )
```

The `.value` used on `self.alert_type` is retrieving the original string from the enum.

### ✅ Checkpoint Tests

Students should be able to:
```
print(AlertType.FILE_HASH_DETECTED)
# AlertType.FILE_HASH_DETECTED

print(AlertType.FILE_HASH_DETECTED.value)
# file_hash_detected
```

And:
```
print(alerts[0].alert_type == AlertType.LOGIN_FAILURE)
# True or False
```

---

## Step 6: Write a Report to a File

Write a simple report to `incident_summary.txt`:

```python
with open("incident_summary.txt", "w", encoding="utf-8") as out:
    out.write("Incident Triage Summary\n")
    out.write("======================\n")
    out.write(f"Total alerts: {len(alerts)}\n")
    out.write(f"HIGH: {high}\n")
    out.write(f"MEDIUM: {medium}\n")
    out.write(f"LOW: {low}\n")
```

✅ Checkpoint: You should see `incident_summary.txt` created.

---

# Part 2 — Challenge (Student Must Extend)

Choose **2** of the following challenge upgrades (or require all if you want it harder):

## Challenge A: Add “Internal vs External” Classification

Add a new method to the `Alert` class, you decide the name of the method and ensure that if you call it like `myAlert.myNewMethod()` then it'll achieve the following:
* Add a property on the class called `classification`
* If the indicator is an IP starting with `10.` or `192.168.` -> then set `classification` to `"internal"`
* Otherwise set `classification` to `"external"`
* If indicator is not an IP, set `classification` to `"N/A"`

Output the number of internal and external classifications in the summary report.

---

## Challenge B: Add a `__str__` Method

Implement:

```python
def __str__(self):
    return f"{self.date} [{self.severity()}] {self.alert_type} on {self.asset} -> {self.indicator}"
```

Then print all alerts neatly using:

```python
for a in alerts:
    print(a)
```

---

## Challenge C: Add “Escalate” Rule

Create logic that flags alerts for escalation. The logic should accomplish the following:
* Add a property onto the `Alert` class that is a boolean (true/false) called `is_escalated`
* Any alert with a severity of `HIGH` should be escalated
* Escalate `MEDIUM` alerts if they involve any `hr-laptop` or `hr-desktop`
* Escalate any severity alert if it involves any `finance-laptop`

Add an `escalate()` method on the `Alert` class that sets the `is_escalated` to `true`.

---

## Challenge D: Add User Input Filter

Ask the user to type a severity level (HIGH/MEDIUM/LOW) and only print those alerts.

---

# 📦 Deliverables

Submit:

1. `incident_tracker.py`
2. `incident_summary.txt`
3. A screenshot (or pasted text) of program output
4. A short reflection (2–4 sentences):

   * What did classes make easier?
   * What part was hardest?
   * What ideas do you have about how to make this better?

---

# 📝 Rubric (50 points)

| Category                             | Points |
| ------------------------------------ | -----: |
| Reads + parses file correctly        |     10 |
| Class exists with correct attributes |     10 |
| Severity method works correctly      |     10 |
| Summary counts correct               |     10 |
| Report file created and readable     |      5 |
| Challenge extensions (2 chosen)      |      5 |
