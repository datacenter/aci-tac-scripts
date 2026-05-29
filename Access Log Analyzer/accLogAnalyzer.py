#!/usr/bin/env python
from datetime import datetime, timedelta
import argparse
import os
import re

ACCLOG_REGEX = r"^(?P<RemoteAddrV6>::ffff|):?(?P<RemoteAddr>\d+\.\d+\.\d+\.\d+)\s?(?:\((?:-|(?P<Real_RemoteAddrV6>::ffff|):?(?P<Real_RemoteAddr>\d+\.\d+\.\d+\.\d+))\)(?:.*))?.+\[(?P<TimeLocal>\d+\/\w+\/\d{4}:\d+:\d+:\d+).+]\s?\"(?P<Request>.*)\" (?P<Status>\d{3}) (?P<BodyBytesSent>\d+) \"(?P<HttpReferrer>[^\"]+)\" \"(?P<HttpUserAgent>[^\"]+)\"(?:\s+\"(?P<UpstreamAddr>[^\"]*)\"\s+rt=(?P<RequestTime>[\d.]+)\s+urt=(?P<UpstreamResponseTime>[\d.-]+))?"


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


def analyze(entries, filename, slow_threshold, top_n):
    summary = ""
    request_remote_addr_count = {}
    request_real_ip_count = {}
    request_user_agent_count = {}
    response_status_count = {}
    upstream_addr_count = {}
    rt_by_ip = {}
    rt_by_status = {}
    timed_entries = []
    socket_entries = []
    no_upstream_count = 0

    burst_output = "Burst Analysis - Checking for 15+ requests-per-second\n"
    timestamp_agg = []
    burst_threshold = 15
    entry2 = None
    entry_gen = check_for_bursts(entries)

    ## Get First and Last entries for Timerange of log
    summary += "Access Log Time Analysis Summary: \n\n"
    summary += "    Analyzed File: {filename}\n".format(filename=filename)
    summary += "    Log Start Time: {start}\n".format(start=entries[0]["TimeLocal"])
    summary += "    Log End Time: {end}\n\n".format(end=entries[-1]["TimeLocal"])
    summary += "    Total # of Requests: {req_len}\n\n".format(req_len=len(entries))

    log_start = datetime.strptime(entries[0]["TimeLocal"], "%d/%b/%Y:%H:%M:%S")
    log_end = datetime.strptime(entries[-1]["TimeLocal"], "%d/%b/%Y:%H:%M:%S")
    time_diff = log_end - log_start
    time_diff_seconds = time_diff.total_seconds()
    time_diff_minutes = time_diff_seconds / 60
    qry_per_second_avg = len(entries) / time_diff_seconds if time_diff_seconds > 0 else len(entries)

    summary += "    Time Coverage: {time_diff_minutes} Minutes ({time_diff_seconds} s)\n".format(
        time_diff_minutes=time_diff_minutes, time_diff_seconds=time_diff_seconds
    )
    summary += "    Avg # of Reqs: {round_req} Queries per second\n\n".format(
        round_req=round(qry_per_second_avg, 2)
    )

    for entry in entries:
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

        ## UPSTREAM ADDR SUMMARY
        if entry["UpstreamAddr"] is not None:
            upstream_addr = entry["UpstreamAddr"] or "-"
            if upstream_addr not in upstream_addr_count:
                upstream_addr_count[upstream_addr] = 1
            else:
                upstream_addr_count[upstream_addr] += 1

        ## REQUEST TIME ANALYSIS
        if entry["RequestTime"] is not None:
            rt = float(entry["RequestTime"])
            if entry["Status"] == "101":
                socket_entries.append((rt, entry))
            else:
                timed_entries.append((rt, entry))
                ip = entry["RemoteAddr"]
                if ip not in rt_by_ip:
                    rt_by_ip[ip] = []
                rt_by_ip[ip].append(rt)
                status = entry["Status"]
                if status not in rt_by_status:
                    rt_by_status[status] = []
                rt_by_status[status].append(rt)
                if entry["UpstreamResponseTime"] == "-":
                    no_upstream_count += 1

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
                    burst_output += "    " + burst_str + "\n"

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
        avg = round((float(count) / len(entries)) * 100, 2)
        summary += "    Remote addr '{remote_addr}' request count: {count} (%{avg} of total reqs) \n".format(
            remote_addr=remote_addr, count=count, avg=avg
        )

    ## REAL_IP SUMMARY
    real_ip_data = {k: v for k, v in request_real_ip_count.items() if k is not None}
    if real_ip_data:
        summary += "\nReal IP Summary (Proxy-in-play): \n\n"
        for remote_addr, count in real_ip_data.items():
            avg = round((float(count) / len(entries)) * 100, 2)
            summary += "    Real IP '{remote_addr}' request count: {count} (%{avg} of total reqs) \n".format(
                remote_addr=remote_addr, count=count, avg=avg
            )

    ## USER-AGENT SUMMARY
    summary += "\nUser-Agent Summary: \n\n"
    for user_agent, count in request_user_agent_count.items():
        avg = round((float(count) / len(entries)) * 100, 2)
        summary += "    User-agent '{user_agent}...' request count: {count} (%{avg} of total reqs) \n".format(
            user_agent=user_agent[:15], count=count, avg=avg
        )

    ## RESPONSE STATUS SUMMARY
    summary += "\nResponse Status Summary: \n\n"
    for code, count in response_status_count.items():
        avg = round((float(count) / len(entries)) * 100, 2)
        summary += "    Response code '{code}' count: {count} (%{avg} of total reqs) \n".format(
            code=code, count=count, avg=avg
        )

    ## UPSTREAM ADDR SUMMARY
    if upstream_addr_count:
        summary += "\nUpstream Address Summary: \n\n"
        for upstream_addr, count in upstream_addr_count.items():
            avg = round((float(count) / len(entries)) * 100, 2)
            summary += "    Upstream addr '{upstream_addr}' count: {count} (%{avg} of total reqs) \n".format(
                upstream_addr=upstream_addr, count=count, avg=avg
            )

    ## REQUEST TIME SUMMARY (excludes HTTP 101 WebSocket connections)
    if timed_entries:
        rt_all = [rt for rt, _ in timed_entries]
        rt_avg = round(sum(rt_all) / len(rt_all), 3)
        rt_min = round(min(rt_all), 3)
        rt_max = round(max(rt_all), 3)
        slow_count = sum(1 for rt in rt_all if rt >= slow_threshold)
        summary += "\nRequest Time (rt) Summary ({n} entries, HTTP 101/WebSocket excluded):\n\n".format(n=len(timed_entries))
        summary += "    Overall avg rt: {avg}s  min: {min}s  max: {max}s\n".format(
            avg=rt_avg, min=rt_min, max=rt_max
        )
        summary += "    Requests exceeding {threshold}s threshold: {slow_count} (%{pct} of timed reqs)\n".format(
            threshold=slow_threshold,
            slow_count=slow_count,
            pct=round((float(slow_count) / len(rt_all)) * 100, 2),
        )
        summary += "    No-upstream requests (urt=-): {no_upstream_count} (%{pct} of timed reqs)\n\n".format(
            no_upstream_count=no_upstream_count,
            pct=round((float(no_upstream_count) / len(rt_all)) * 100, 2),
        )
        summary += "    Avg rt by Client IP:\n"
        for ip, times in rt_by_ip.items():
            ip_avg = round(sum(times) / len(times), 3)
            summary += "        {ip}: avg {avg}s over {count} requests\n".format(
                ip=ip, avg=ip_avg, count=len(times)
            )
        summary += "\n    Avg rt by HTTP Status:\n"
        for status, times in rt_by_status.items():
            status_avg = round(sum(times) / len(times), 3)
            summary += "        {status}: avg {avg}s over {count} requests\n".format(
                status=status, avg=status_avg, count=len(times)
            )
        sorted_entries = sorted(timed_entries, key=lambda x: x[0], reverse=True)
        top_entries = sorted_entries[:top_n]
        summary += "\n    Top {top_n} Slowest Requests:\n".format(top_n=min(top_n, len(sorted_entries)))
        for rt, entry in top_entries:
            summary += "        rt={rt}s [{time}] {ip} \"{request}\" {status}\n".format(
                rt=rt,
                time=entry["TimeLocal"],
                ip=entry["RemoteAddr"],
                request=entry["Request"],
                status=entry["Status"],
            )

    ## WEBSOCKET / LONG-LIVED CONNECTION SUMMARY (HTTP 101)
    if socket_entries:
        sock_rt_all = [rt for rt, _ in socket_entries]
        sock_avg = round(sum(sock_rt_all) / len(sock_rt_all), 3)
        sock_min = round(min(sock_rt_all), 3)
        sock_max = round(max(sock_rt_all), 3)
        summary += "\nWebSocket Connection Summary (HTTP 101, {n} connections):\n\n".format(n=len(socket_entries))
        summary += "    Connection duration avg: {avg}s  min: {min}s  max: {max}s\n".format(
            avg=sock_avg, min=sock_min, max=sock_max
        )
        summary += "    Note: rt for HTTP 101 reflects total connection lifetime, not request latency.\n\n"
        sorted_sockets = sorted(socket_entries, key=lambda x: x[0], reverse=True)
        summary += "    Longest Open Connections:\n"
        for rt, entry in sorted_sockets:
            summary += "        duration={rt}s [{time}] {ip} \"{request}\"\n".format(
                rt=rt,
                time=entry["TimeLocal"],
                ip=entry["RemoteAddr"],
                request=entry["Request"][:80],
            )

    summary += "\n=============Summary End================\n\n"
    return summary, burst_output


def main(filename, output_location, slow_threshold, top_n, window_minutes):
    timenow = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    mprint("Parsing START")
    with open(filename, "r") as file:
        access_dict = parseLogs(file)
    mprint("Parsing FIN. Begin Summary.")
    mprint("Got {num} lines to summarize".format(num=len(access_dict)))

    ## Full analysis
    summary, burst_output = analyze(access_dict, filename, slow_threshold, top_n)

    output_file = output_location + "/acclogAnalysis_" + timenow + ".output"
    with open(output_file, "w") as f:
        f.write(summary)
    mprint("Wrote Summary to " + output_file)

    burst_output_file = output_location + "/acclogBurstAnalysis_" + timenow + ".output"
    with open(burst_output_file, "w") as f:
        f.write(burst_output)
    mprint("Wrote Burst analysis to " + burst_output_file)

    ## Windowed analysis
    last_ts = datetime.strptime(access_dict[-1]["TimeLocal"], "%d/%b/%Y:%H:%M:%S")
    cutoff = last_ts - timedelta(minutes=window_minutes)
    windowed = [
        e for e in access_dict
        if datetime.strptime(e["TimeLocal"], "%d/%b/%Y:%H:%M:%S") >= cutoff
    ]
    if windowed:
        mprint(
            "Running windowed analysis: last {w} minutes ({n} entries, cutoff: {cutoff})".format(
                w=window_minutes, n=len(windowed), cutoff=cutoff.strftime("%d/%b/%Y:%H:%M:%S")
            )
        )
        window_summary, window_burst = analyze(windowed, filename, slow_threshold, top_n)
        window_label = "window_{w}m_".format(w=window_minutes)
        window_header = "Time Window: Last {w} minutes  |  Cutoff: {cutoff}  |  Entries: {n}\n\n".format(
            w=window_minutes, cutoff=cutoff.strftime("%d/%b/%Y:%H:%M:%S"), n=len(windowed)
        )
        window_output_file = output_location + "/acclogAnalysis_" + window_label + timenow + ".output"
        with open(window_output_file, "w") as f:
            f.write(window_header)
            f.write(window_summary)
        mprint("Wrote windowed summary to " + window_output_file)

        window_burst_file = output_location + "/acclogBurstAnalysis_" + window_label + timenow + ".output"
        with open(window_burst_file, "w") as f:
            f.write(window_header)
            f.write(window_burst)
        mprint("Wrote windowed burst analysis to " + window_burst_file)
    else:
        mprint(
            "No entries found within the last {w} minutes window (cutoff: {cutoff}). Skipping windowed analysis.".format(
                w=window_minutes, cutoff=cutoff.strftime("%d/%b/%Y:%H:%M:%S")
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-f",
        "--file",
        dest="filename",
        default="/var/log/dme/log/accessproxy.log",
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
    parser.add_argument(
        "-t",
        "--threshold",
        dest="slow_threshold",
        default=5.0,
        type=float,
        help="Request time threshold in seconds for slow request flagging (default: 5.0). NOTE: rt/urt analysis only available for accessproxy.log on ACI 6.2+",
        required=False,
    )
    parser.add_argument(
        "-n",
        "--top-n",
        dest="top_n",
        default=20,
        type=int,
        help="Number of slowest requests to include in output (default: 20). NOTE: rt/urt analysis only available for accessproxy.log on ACI 6.2+",
        required=False,
    )
    parser.add_argument(
        "-w",
        "--window",
        dest="window_minutes",
        default=5,
        type=int,
        help="Time window in minutes relative to the last log entry for the windowed analysis output (default: 5)",
        required=False,
    )
    args = parser.parse_args()
    try:
        file = args.filename
        output_location = args.output_location
        if os.path.exists(file):
            mprint("Found {file}, beginning accLogAnalyzer".format(file=file))
            main(file, output_location, args.slow_threshold, args.top_n, args.window_minutes)
        else:
            mprint("{file} not found or not a file".format(file=file))
    except KeyboardInterrupt as e:
        mprint("Keyboard break hit")
