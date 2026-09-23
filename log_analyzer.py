import re
import tkinter as tk
from tkinter import filedialog
import numpy

from Attempt import Attempt


def importFile():
    path=filedialog.askopenfilename(title='Select the file', filetypes=[('txt files', '*.txt')])
    if path:
        readFile(path)

def readFile(path):
    global file
    try:
        file=open(path, "r")
        filePathLabel.config(text=path)
        mainTask()

    except Exception as e:
        filePathLabel.config(text=f'Error: {e}')


def readAttemptsFromFile(file)->list[Attempt]:
    attempts = []
    # First read in the file
    for line in file:
        parts=line.strip().split()
            
        if len(parts)<3:
            continue
    
        # Check if the line is a login attempt (either failed or successful)
        if("Failed password" in line or "Accepted password" in line):
    
            timeStampParts=parts[2].strip().split(":")
            timeStamp=int(timeStampParts[0])*3600+int(timeStampParts[1])*60+int(timeStampParts[2])
            IP_addess=re.search(r'from\s+([0-9a-fA-F:\.]+)', line)
            username = re.search(r'for\s+(?:invalid user\s+)?(\S+)\s+from', line)
                
            if IP_addess is None or username is None:
                continue
            IP_addess=IP_addess.group(1)
            username=username.group(1)
    
            attempt = Attempt(
                date=parts[0]+" "+parts[1],
                timestamp=timeStamp,
                username=username,
                ip_address=IP_addess,
                is_successful='Failed password' not in line
            )
    
            attempts.append(attempt)
    return attempts

def checkBruteForce(attempts, date)->set:
    """
    Checks for brute-force login attempts in the given list of attempts.
    Returns a set of suspicious IP addresses.
    """
    failed_IPs = {}
    suspicious = set()
    
    for attempt in attempts:
        if not attempt.is_successful:
            failed_IPs[attempt.ip_address] = failed_IPs.get(attempt.ip_address, [])
            failed_IPs[attempt.ip_address].append(attempt.timestamp)

    for ip_address, timestamps in failed_IPs.items():
        if checkBruteForceForIp(timestamps):
            suspicious.add(date+"\t: "+ip_address+" (Brute Force)")

    return suspicious

# Looks for brute-force login tries in one IP's timestamps list using sliding window
def checkBruteForceForIp(timeList)->bool:
    timeList=sorted(timeList)
    windowSize=3600
    threshold=5
    left=0

    for right in range(len(timeList)):
        while timeList[right]-timeList[left]>windowSize:
            left+=1
        counter=right-left+1
        if counter>=threshold:
            return True
        
    return False


def checkAnomalies(attempts, date)->set:
    failed_IPs = {}
    suspicious = set()

    for attempt in attempts:
        if not attempt.is_successful:
            failed_IPs[attempt.ip_address] = failed_IPs.get(attempt.ip_address, [])
            failed_IPs[attempt.ip_address].append(attempt.timestamp)

    #if there are no failed login attempts, return an empty set
    if not failed_IPs:
        return suspicious

    
    # Calculate the 95th percentile of failed login attempts for the day
    percentile=numpy.percentile(list(len(attempts) for attempts in failed_IPs.values()), 95)
    print(percentile)

    # Go through on each IP address attempts and check if it exceeds the 95th percentile
    for IP_addess, attempts in failed_IPs.items():
        if len(attempts)>percentile:
            suspicious.add(date+"\t: "+IP_addess+" (Above 95th percentile)")

    return suspicious


def checkUsernames(attempts, threshold, date)->set:
    username_counts = {}
    usernames_in_danger = set()

    for attempt in attempts:
        if not attempt.is_successful:
            username_counts[attempt.username] = username_counts.get(attempt.username, 0) + 1

    for username, count in username_counts.items():
        if count >= threshold:
            usernames_in_danger.add(date+"\t: "+username+" (Username multiple failed login attempts)")
    return usernames_in_danger

def mainTask():
    attempts_per_date = {}

    # Set because we don't want duplicates
    suspicious_ips=set()
    usernames_in_danger=set()


    attempts = readAttemptsFromFile(file)

    # Group the attempts by day
    for attempt in attempts:
        date = attempt.date
        attempts_per_date[date]=attempts_per_date.get(date, [])
        attempts_per_date[date].append(attempt)

    for date in attempts_per_date.keys():
        suspicious_ips.update(checkBruteForce(attempts_per_date[date], date))
        suspicious_ips.update(checkAnomalies(attempts_per_date[date], date))
        usernames_in_danger.update(checkUsernames(attempts_per_date[date], 5, date))


    file.close()
    suspicious_ips=sorted(suspicious_ips)
    usernames_in_danger=sorted(usernames_in_danger)
    outputIPs.config(text="\n".join(suspicious_ips))
    outputUsernames.config(text="\n".join(usernames_in_danger))

    return suspicious_ips

window=tk.Tk()
window.geometry("750x750")
window.title('SSH Log Analyzer')

baseSettingsBar=tk.Frame(window)

baseSettingsBar.pack(side='top', anchor='nw', pady=10, padx=10)

uploadButton=tk.Button(baseSettingsBar, text='Import log text File', command=importFile)
uploadButton.pack(side='left')

filePathLabel = tk.Label(baseSettingsBar, text='')
filePathLabel.pack(side='right')

outputs=tk.Frame(window)
outputs.pack(side='top', anchor='nw', pady=10, padx=10)

outputIP_Label=tk.Label(outputs, text='Suspicious login attempts from these IPs:', font=('Consolas', 11))
outputIP_Label.pack(side='top', anchor='nw', pady=(10, 0), padx=10)

outputIPs=tk.Label(outputs, text='', font=('Consolas', 11), justify='left', anchor='nw')
outputIPs.pack(side='top', anchor='nw', pady=5, padx=10)

outputUsernames_Label=tk.Label(outputs, text='Usernames in danger:', font=('Consolas', 11))
outputUsernames_Label.pack(side='top', anchor='nw', pady=(10, 0), padx=10)

outputUsernames=tk.Label(outputs, text='', font=('Consolas', 11), justify='left', anchor='nw')
outputUsernames.pack(side='top', anchor='nw', pady=5, padx=10)

window.mainloop()