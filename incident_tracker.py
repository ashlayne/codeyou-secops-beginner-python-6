def main():

    from enum import Enum
    import ipaddress
    import os
    import sys

    # region filename collector
    #Gemini helped with this bit of scripting, to allow for entry of a filename on run.
    filename = ""

    while not os.path.exists(filename):
         filename = input("Please enter the filename in this directory you wish to review (or type quit to exit): ")
         if filename.lower() == "quit":
              sys.exit()
         if not os.path.exists(filename):
            print(f"Error: No such filename {filename}. Please try again.")
    # endregion

    # region filename static
    # #To test with the same file instead of typing it every time I test
    # with open("alerts-test.txt", "r", encoding="utf-8") as f:
    #      lines = f.read().splitlines()
    # endregion
    
    #For final program
    with open(filename, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()

    print(f"Loaded {len(lines)} alerts.")

#     # is duplicating my records counts 
#     records = []
#     for line in lines[1:]:
#          date, alert_type, asset, indicator = line.split(",")
#          records.append((date, alert_type, asset, indicator))

#     print(records[0])

    # region AlertType class
    class AlertType(Enum):
        LOGIN_FAILURE = "login_failure"
        LOGIN_SUCCESS = "login_success"
        FILE_HASH_DETECTED = "file_hash_detected"
        DNS_QUERY = "dns_query"
        PORT_SCAN = "port_scan"
        PASSWORD_RESET = "password_reset"
        LOGOUT = "logout"
        LOGIN_ATTEMPT = "login_attempt"
        HTTP_REQUEST = "http_request"
        QUARANTINE_TRIGGERED = "quarantine_triggered"
        MALWARE_ALERT = "malware_alert"
        SCAN_COMPLETED = "scan_completed"
    # endregion

    # region Alert class
    class Alert:
        def __init__(self, date, alert_type, asset, indicator):
              self.date = date
              self.alert_type = alert_type
              #Now an AlertType Enum
              self.asset = asset
              self.indicator = indicator
              
        def severity(self):
            if self.alert_type == AlertType.FILE_HASH_DETECTED:
                  return "HIGH"
            elif self.alert_type in [AlertType.PORT_SCAN, AlertType.DNS_QUERY]:
                  return "MEDIUM"
            else:
                  return "LOW"

        def classification(self): #added code for Challenge A - see notes by the Challenge A comment
             try:
                  ip = ipaddress.ip_address(self.indicator)
                  if ip.is_private:
                       return "INTERNAL"
                  else:
                       return "EXTERNAL"
             except ValueError:
                  return "NON-IP/OTHER" #for file hashes or DNS domains

        #Challenge B     
        def __str__(self):
            return (
              f"{self.date} [{self.severity()}]"
              f"{self.alert_type.value} on {self.asset} -> {self.indicator}"
            )
        
    # endregion        

    alerts = []
    
    # for date, alert_type, asset, indicator in records:
    #      alerts.append(Alert(date, alert_type, asset, indicator))
    
    for line in lines[1:]:
         date, alert_type_str, asset, indicator = line.split(",")
         alert_type = AlertType(alert_type_str)
         new_alert = Alert(date, alert_type, asset, indicator)
         alerts.append(new_alert)

    print(alerts[0].alert_type, alerts[0].severity())

    high = 0
    medium = 0
    low = 0
    internal = 0
    external = 0
    na = 0

    for a in alerts:
         sev = a.severity()
         if sev == "HIGH":
              high += 1
         elif sev == "MEDIUM":
              medium += 1
         else:
              low += 1

    # Challenge A - I used Gemini to help me figure this out, but wrote what I could myself.

    for a in alerts:
         ip_class = a.classification()
         if ip_class == "INTERNAL":
              internal += 1
         elif ip_class == "EXTERNAL":
              external += 1
         else:
              na += 1

    for a in alerts:
        print(f"Alert on {a.asset}: Source is {a.classification()}") #Calling the IP classification from the Alert class, from Challenge A
    
    # print(AlertType.FILE_HASH_DETECTED)
    # AlertType.FILE_HASH_DETECTED

    # print(AlertType.FILE_HASH_DETECTED.value)
    # # file_hash_detected

    # print(alerts[0].alert_type == AlertType.LOGIN_FAILURE)
    # # True or False

    print("\n=== Summary ===")
    print(f"HIGH: {high}")
    print(f"MEDIUM: {medium}")
    print(f"LOW: {low}")
    print(f"Internal IP attempts: {internal}") #Challenge A code segment
    print(f"External IP attempts: {external}") #Challenge A code segment
    print(f"Attempts Not Valid: {na}") #Challenge A code segment
    for a in alerts: #Challenge B code segment
         print(a)

    with open("incident_summary.txt", "w", encoding="utf-8") as out:
        out.write("Incident Triage Summary\n")
        out.write("======================\n")
        out.write(f"Total alerts: {len(alerts)}\n")
        out.write(f"HIGH: {high}\n")
        out.write(f"MEDIUM: {medium}\n")
        out.write(f"LOW: {low}\n")
        out.write("======================\n")
        out.write(f"Internal IP attempts: {internal}\n") #Challenge A code segment
        out.write(f"External IP attempts: {external}\n") #Challenge A code segment
        out.write(f"Attempts Not Valid: {na}\n") #Challenge A code segment
        #Challenge B - write this to the file too 
        out.write("======================\n")
        out.write("====== Alerts ========\n")
        out.write("======================\n")
        for a in alerts:
             out.write(str(a) + "\n")

if __name__ == '__main__':
	main()