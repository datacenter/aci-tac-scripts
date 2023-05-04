#!/usr/bin/env python
from datetime import datetime
import argparse
import os
import re

ACCLOG_REGEX = r"^(?P<RemoteAddrV6>::ffff|):?(?P<RemoteAddr>\d+\.\d+\.\d+\.\d+) \((?:-|(?P<Real_RemoteAddrV6>::ffff|):?(?P<Real_RemoteAddr>\d+\.\d+\.\d+\.\d+))\)(?:.*) \[(?P<TimeLocal>\d+\/\w+\/\d{4}:\d+:\d+:\d+).+]\s?\"(?P<Request>.*)\" (?P<Status>\d{3}) (?P<BodyBytesSent>\d+) \"(?P<HttpReferrer>.+)\" \"(?P<HttpUserAgent>.+)\""


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


def check_for_bursts(access_dict):
    i = 0
    while i < len(access_dict):
        yield access_dict[i]
        i += 1


def main(filename, output_location):
    timenow = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    mprint("Parsing START")
    with open(filename, "r") as file:
        access_dict = parseLogs(file)
    mprint("Parsing FIN. Begin Summary.")
    mprint("Got {num} lines to summarize".format(num=len(access_dict)))

    summary = ""
    request_remote_addr_count = {}
    request_real_ip_count = {}
    request_user_agent_count = {}
    response_status_count = {}

    burst_output = "Burst Analysis - Checking for 15+ requests-per-second\n"
    timestamp_agg = []
    burst_threshold = 15
    entry2 = None
    entry_gen = check_for_bursts(access_dict)

    ## Get First and Last entries for Timerange or log
    summary += "Access Log Time Analysis Summary: \n\n"
    summary += "    Log Start Time: {start}\n".format(start=access_dict[0]["TimeLocal"])
    summary += "    Log End Time: {end}\n\n".format(end=access_dict[-1]["TimeLocal"])
    summary += "    Total # of Requests: {req_len}\n\n".format(req_len=len(access_dict))

    log_start = datetime.strptime(access_dict[0]["TimeLocal"], "%d/%b/%Y:%H:%M:%S")
    log_end = datetime.strptime(access_dict[-1]["TimeLocal"], "%d/%b/%Y:%H:%M:%S")
    time_diff = log_end - log_start
    time_diff_seconds = time_diff.total_seconds()
    time_diff_minutes = time_diff_seconds / 60
    qry_per_second_avg = len(access_dict) / time_diff_seconds

    summary += "    Time Coverage: {time_diff_minutes} Minutes ({time_diff_seconds} s)\n".format(
        time_diff_minutes=time_diff_minutes, time_diff_seconds=time_diff_seconds
    )
    summary += "    Avg # of Reqs: {round_req} Queries per second\n\n".format(
        round_req=round(qry_per_second_avg, 2)
    )

    for entry in access_dict:
        ## REMOTE ADDR SUMMARY
        if entry["RemoteAddr"] not in request_remote_addr_count.keys():
            request_remote_addr_count[entry["RemoteAddr"]] = 1
        else:
            request_remote_addr_count[entry["RemoteAddr"]] += 1

        ## REAL_IP SUMMARY
        if entry["Real_RemoteAddr"] not in request_real_ip_count.keys():
            request_real_ip_count[entry["Real_RemoteAddr"]] = 1
        else:
            request_real_ip_count[entry["Real_RemoteAddr"]] += 1

        ## USER-AGENT SUMMARY
        if entry["HttpUserAgent"] not in request_user_agent_count.keys():
            request_user_agent_count[entry["HttpUserAgent"]] = 1
        else:
            request_user_agent_count[entry["HttpUserAgent"]] += 1

        ## RESPONSE STATUS SUMMARY
        if entry["Status"] not in response_status_count.keys():
            response_status_count[entry["Status"]] = 1
        else:
            response_status_count[entry["Status"]] += 1

        ## BURST ANALYSIS
        burst_temp = []
        burst = False
        analyzing = True

        if not entry2:
            entry2 = next(entry_gen)

        if entry["TimeLocal"] not in [d["timestamp"] for d in timestamp_agg]:
            while analyzing:
                if entry["TimeLocal"] == entry2["TimeLocal"]:
                    burst_temp.append(entry2)
                    try:
                        entry2 = next(entry_gen)
                    except StopIteration:
                        analyzing = False

                else:
                    analyzing = False

            ## Display Burst output
            tmp_burst_count = len(burst_temp)
            if tmp_burst_count >= burst_threshold:
                burst = True
                burst_output += (
                    "\n{burst_count} Request Burst found at {entry_time}:\n".format(
                        burst_count=tmp_burst_count,
                        entry_time=entry["TimeLocal"],
                    )
                )

                for bentry in burst_temp:
                    burst_str = " ".join(str(x) for x in bentry.values())
                    burst_output += f"    " + burst_str + "\n"

            ## Write the burst summary dict
            timestamp_summary = {
                "timestamp": entry["TimeLocal"],
                "count": tmp_burst_count,
                "burst": burst,
            }
            timestamp_agg.append(timestamp_summary)

    ## BURST ANALYSIS SUMMARY
    total_bursts = len([i for i in timestamp_agg if i["burst"] == True])
    summary += "    Burst Summary: {total_bursts} 15+ requests-per-second bursts found.\n\n".format(
        total_bursts=total_bursts
    )

    ## REMOTE ADDR SUMMARY
    summary += "Remote Address Summary: \n\n"
    for remote_addr, count in request_remote_addr_count.items():
        avg = round((float(count) / len(access_dict)) * 100, 2)
        summary += "    Remote addr '{remote_addr}' request count: {count} (%{avg} of total reqs) \n".format(
            remote_addr=remote_addr, count=count, avg=avg
        )

    ## REAL_IP SUMMARY
    summary += "\nReal IP Summary (Proxy-in-play): \n\n"
    for remote_addr, count in request_real_ip_count.items():
        avg = round((float(count) / len(access_dict)) * 100, 2)
        summary += "    Real IP '{remote_addr}' request count: {count} (%{avg} of total reqs) \n".format(
            remote_addr=remote_addr, count=count, avg=avg
        )

    ## USER-AGENT SUMMARY
    summary += "\nUser-Agent Summary: \n\n"
    for user_agent, count in request_user_agent_count.items():
        avg = round((float(count) / len(access_dict)) * 100, 2)
        summary += "    User-agent '{user_agent}...' request count: {count} (%{avg} of total reqs) \n".format(
            user_agent=user_agent[:15], count=count, avg=avg
        )

    ## RESPONSE STATUS SUMMARY
    summary += "\nResponse Status Summary: \n\n"
    for code, count in response_status_count.items():
        avg = round((float(count) / len(access_dict)) * 100, 2)
        summary += "    Response code '{code}' count: {count} (%{avg} of total reqs) \n".format(
            code=code, count=count, avg=avg
        )

    summary += "\n=============Summary End================\n\n"

    output_file = output_location + "/acclogAnalysis_" + timenow + ".output"
    with open(output_file, "w") as f:
        f.write(summary)

    mprint("Run finished, Wrote Summary to " + output_file)

    burst_output_file = output_location + "/acclogBurstAnalysis_" + timenow + ".output"
    with open(burst_output_file, "w") as f:
        f.write(burst_output)

    mprint("Wrote Burst analysis to " + burst_output_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="filename",
        default="/var/log/dme/log/access.log",
        help="Fullpath to access.log file to analyze",
        required=False,
        nargs="?",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_location",
        default="/data/techsupport",
        help="Directory to write output files",
        required=False,
        nargs="?",
    )
    args = parser.parse_args()
    try:
        file = args.filename
        output_location = args.output_location
        if os.path.exists(file):
            mprint("Found {file}, beginning accLogAnalyzer".format(file=file))
            main(file, output_location)
        else:
            mprint("{file} not found or not a file".format(file=file))
    except KeyboardInterrupt as e:
        mprint("Keyboard break hit")
