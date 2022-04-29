#!/usr/bin/env python
import argparse
import os
import re
from datetime import datetime
import io

ACCLOG_REGEX = r'^(?P<RemoteAddrV6>::ffff|):?(?P<RemoteAddr>\d+\.\d+\.\d+\.\d+) (?:|\(.+\) )- (.*) \[(?P<TimeLocal>\d+\/\w+\/\d{4}:\d+:\d+:\d+).+]\s?\"(?P<Request>.*)\" (?P<Status>\d{3}) (?P<BodyBytesSent>\d+) \"(?P<HttpReferrer>.+)\" \"(?P<HttpUserAgent>.+)\"'


def mprint(message):
    timenow = datetime.now().strftime("%d-%b-%Y (%H:%M:%S.%f)")
    print("{timenow} {message}".format(timenow=timenow, message=message))


def parseLogs(file):
    output = []
    for line in file:
        try:
            m = re.match(ACCLOG_REGEX, line)
            output.append(m.groupdict())
        except AttributeError:
            mprint("RE ERR:{line}".format(line=line))
    return output


def task(filename):
    timenow = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    summary = ""
    output = ""
    mprint("Parsing START")
    with open(filename, 'r') as file:
        access_dict = parseLogs(file)

    mprint("Parsing FIN, begin analysis")

    mprint("Got {num} lines to analyze, this could take a few minutes...".format(num=len(access_dict)))

    ## Get First and Last entries for Timerange or log
    summary += "Access Log Time Analysis Summary: \n\n"
    summary += "    Log Start Time: {start}\n".format(start=access_dict[0]['TimeLocal'])
    summary += "    Log End Time: {end}\n\n".format(end=access_dict[-1]['TimeLocal'])
    summary += "    Total # of Requests: {req_len}\n\n".format(req_len=len(access_dict))

    log_start = datetime.strptime(access_dict[0]["TimeLocal"], "%d/%b/%Y:%H:%M:%S")
    log_end = datetime.strptime(access_dict[-1]["TimeLocal"], "%d/%b/%Y:%H:%M:%S")
    time_diff = log_end - log_start
    time_diff_seconds = time_diff.total_seconds()
    time_diff_minutes = time_diff_seconds / 60
    qry_per_second_avg = len(access_dict) / time_diff_seconds

    summary += "    Time Coverage: {time_diff_minutes} Minutes ({time_diff_seconds} s)\n".format(
        time_diff_minutes=time_diff_minutes, time_diff_seconds=time_diff_seconds)
    summary += "    Avg # of Reqs: {round_req} Queries per second\n\n".format(round_req=round(qry_per_second_avg, 2))

    output += "\n=============Summary End================\n\n"
    output += "Burst Analysis - Checking for 15+ requests-per-second\n"

    burst_timestamps = []
    request_remote_addr_count = {}
    request_user_agent_count = {}
    response_status_count = {}
    burst_display_limit = 10

    for entry in access_dict:
        burst_temp = []

        ## FOR REMOTE ADDR SUMMARY
        if entry["RemoteAddr"] not in request_remote_addr_count.keys():
            request_remote_addr_count[entry["RemoteAddr"]] = 1
        else:
            request_remote_addr_count[entry["RemoteAddr"]] += 1

        ## FOR USER-AGENT SUMMARY
        if entry["HttpUserAgent"] not in request_user_agent_count.keys():
            request_user_agent_count[entry["HttpUserAgent"]] = 1
        else:
            request_user_agent_count[entry["HttpUserAgent"]] += 1

        ## FOR RESPONSE STATUS SUMMARY
        if entry["Status"] not in response_status_count.keys():
            response_status_count[entry["Status"]] = 1
        else:
            response_status_count[entry["Status"]] += 1

        ## FOR BURST ANALYSIS
        for entry2 in access_dict:
            if (entry["TimeLocal"] == entry2["TimeLocal"]) and (entry["TimeLocal"] not in burst_timestamps):
                burst_temp.append(entry2)

        if (len(burst_temp) >= 15) and (entry["TimeLocal"] not in burst_timestamps):
            if (len(burst_timestamps) <= burst_display_limit):
                output += "\n{len_burst_temp} Request Burst found at {entry_time}:\n".format(
                    len_burst_temp=len(burst_temp), entry_time=entry['TimeLocal'])
                '''
                for bentry in burst_temp: ### WIP
                    output += f"    {' '.join(str(x) for x in bentry.values())}\n"
                '''
            burst_timestamps.append(entry["TimeLocal"])

    if len(burst_timestamps) > burst_display_limit:
        output += "\nBurst Display Limit of {burst_display_limit} hit, bursts output stopped\n".format(
            burst_display_limit=burst_display_limit)

    ## BURST ANALYSIS SUMMARY
    summary += "    Burst Summary: {len_burst_timestamps} 15+ requests-per-second bursts found.\n\n".format(
        len_burst_timestamps=len(burst_timestamps))

    ## REMOTE ADDR SUMMARY
    summary += "Remote Address Summary: \n\n"
    for remote_addr, count in request_remote_addr_count.items():
        avg = round((float(count) / len(access_dict)) * 100, 2)
        summary += "    Remote addr '{remote_addr}' request count: {count} (%{avg} of total reqs) \n".format(
            remote_addr=remote_addr, count=count, avg=avg)

    ## USER-AGENT SUMMARY
    summary += "\nUser-Agent Summary: \n\n"
    for user_agent, count in request_user_agent_count.items():
        avg = round((float(count) / len(access_dict)) * 100, 2)
        summary += "    User-agent '{user_agent}...' request count: {count} (%{avg} of total reqs) \n".format(
            user_agent=user_agent[:15], count=count, avg=avg)

    ## RESPONSE STATUS SUMMARY
    summary += "\nResponse Status Summary: \n\n"
    for code, count in response_status_count.items():
        avg = round((float(count) / len(access_dict)) * 100, 2)
        summary += "    Response code '{code}' count: {count} (%{avg} of total reqs) \n".format(code=code, count=count,
                                                                                                avg=avg)

    output_file = '/data/techsupport/acclogAnalysis_' + timenow + '.output'
    with open(output_file, 'w') as f:
        f.write(summary)
        f.write(output)

    mprint("Run finished, Wrote analysis to " + output_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '-f', '--file', dest='filename', default="/var/log/dme/log/access.log",
        help='gunzipped acess.log file to run against', required=False, nargs='+'
    )
    mprint("Starting accLogAnalyzer")
    args = parser.parse_args()
    try:
        file = args.filename
        if os.path.exists(file):
            mprint("Found {file}, beginning run".format(file=file))
            task(file)
        else:
            mprint('{file} not found or not a file'.format(file=file))
    except KeyboardInterrupt as e:
        mprint('Keyboard break hit')