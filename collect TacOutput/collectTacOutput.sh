#*********************************************************************************************************************
#author josephyo
#
#This script automates the collection of objects routinely used troubleshooting ACI problems.
#*********************************************************************************************************************
#!/bin/bash

function log() {
    ts=`date '+%Y-%m-%dT%H:%M:%S'`
    if [[ "$output" == "/dev/null" ]]; then
        echo "$ts $1" 1>>$output
    else
        echo "$ts $1"
    fi
    
}

function log2() {
    if [[ "$output" == "/dev/null" ]]; then
        echo "$1" 1>>$output
    else
        echo "$1"
    fi
    
}

function getTacRecord() {

        count=$(icurl 'http://localhost:7777/api/class/'"$record"'.xml?query-target-filter=and(gt('"$record"'.'"$sortAtt"',"'"$SDATE"'"),lt('"$record"'.'"$sortAtt"',"'"$EDATE"'"))&rsp-subtree-include=count' 2>/dev/null)
        if echo $count | grep -q error; then log "Could not get object count for $record. Error message - $count - skipping object!"; return; fi
        count=$(echo $count | egrep -o "count\S+" | egrep -o "[0-9]+")
        log "There are $count $record objects."
            
        if [[ $count -ge "100000" ]]; then
                pageMax=`echo $count | sed 's/\S\{5\}$//g'`
                pageCount=0
                    while [ "$pageCount" -le "$pageMax" ]
                        do
                            log "Collecting page $pageCount of $record objects..."
                            icurl 'http://localhost:7777/api/class/'"$record"'.xml?query-target-filter=and(gt('"$record"'.'"$sortAtt"',"'"$SDATE"'"),lt('"$record"'.'"$sortAtt"',"'"$EDATE"'"))&order-by='"$record"'.'"$sortAtt"'|desc&page-size=100000&page='"$pageCount"'&rsp-subtree-include=required' > "$record"-"$pageCount".xml 2> "$record"-"$pageCount".out
                                
                                if egrep -ql "Unable to deliver the message, Resolve timeout" "$record"-"$pageCount".xml; then
                                    log "Query for $record page $pageCount timed out. Try reducing time range. Skipping remaining pages for $record"
                                    break
                                else
                                    log "Collection of page $pageCount of $record completed."
                                fi

                            pageCount=$((pageCount+1))
                        done
            else
                log "Collecting $record objects..."
                icurl 'http://localhost:7777/api/class/'"$record"'.xml?query-target-filter=and(gt('"$record"'.'"$sortAtt"',"'"$SDATE"'"),lt('"$record"'.'"$sortAtt"',"'"$EDATE"'"))&order-by='"$record"'.'"$sortAtt"'|desc&page-size=100000' > "$record".xml 2> "$record".out
                log "Collection of $record completed."
        fi
    }    
    
#####HELP
function display_help() {
    echo -e \\n"Help documentation for $0"\\n
    echo "Script will prompt for input or user can supply arguments with below options."
    echo ""
    echo "Supported Options:"
    echo "b:    start date for collected objects.    Ex format: 2019-12-15T00:00:00 "
    echo "        specify \"default\" to choose a starting date one month prior to current time."
    echo "e:    end date for collected objects.        Ex format: 2019-12-15T00:00:00 "
    echo "        specify \"default\" to choose an ending date one month prior to current time."
    echo "o:    Select corresponding number for each object to collect from the following list. keyword 'all' will get all objects. Separate with commas. Ex: 1,2,3,4"
    echo "        *Note, topSystem, fabricNode, and firmwareARunning are automatically included."
cat << 'EOF'
        1. faultInst *collected unfiltered
        2. faultRecord
        3. eventRecord
        4. aaaModLR *collected unfiltered
        5. polDeploymentRecord
        6. epRecord
        7. healthRecord
        8. healthInst *collected unfiltered
EOF
    echo ""
    echo "d:    destination directory for output file."
    echo "q:    run script in quiet mode."    
    echo "To supply all or some arguments to Script: collectTacOutput -b 2019-12-15T00:00:00 -e 2019-12-15T00:00:00 -o 1,2,3,4"
    echo "To run script and follow prompts: collectTacOutput"
    exit 0
}

if [[ "$1" == "--help" ]] || [[ "$1" == "--h" ]]; then
    display_help
    exit 0
fi

#####Take Args from Command
optspec="b:e:o:d:hq"
while getopts "$optspec" optchar; do
  case $optchar in
    b)
        gSDATE=$OPTARG
        ;;
    e)
        gEDATE=$OPTARG
        ;;
    o)
        CMD=$OPTARG
            if [[ $CMD == "all" ]]; then
                CMD="1,2,3,4,5,6,7,8"
            fi            
        echo $CMD | sed 's/,/\n/g' > /tmp/args.txt
        ;;
    d)
        destDir=$OPTARG
        ;;        
    h)
        display_help
        exit 0
        ;;        
    q)
        output=/dev/null
        ;;                
    :)
        echo "Option $OPTARG requires an argument." >&2
        exit 1
        ;;
    \?)
        echo "Invalid option: \"-$OPTARG\"" >&2
        exit 1
        ;;
  esac
done

###Make dir for outputs and get Apic ID
apicID=`icurl 'http://localhost:7777/api/class/fabricNode.json?query-target-filter=eq(fabricNode.name,"'"$HOSTNAME"'")' 2>/dev/null | python -m json.tool | grep "\"id\"" | sed -e 's/\"//g' -e 's/,//g' | awk '{print $2}'`
tacDir="TacOutput`date "+%Y-%m-%dT%H-%M-%S"`"
mkdir /tmp/$tacDir
cd /tmp/$tacDir

###Get Inputs
cat << 'EOF' > /tmp/objects.txt
1. faultInst *collected unfiltered
2. faultRecord
3. eventRecord
4. aaaModLR *collected unfiltered
5. polDeploymentRecord
6. epRecord
7. healthRecord
8. healthInst *collected unfiltered
EOF

if [[ $destDir == "" ]]; then
    destDir=/data/techsupport
fi

if [[ $CMD == "" ]]; then
cat << 'EOF'
Select corresponding numbers of objects to collect. Separate numbers with commas. *Note, topSystem, fabricNode, and firmwareARunning are automatically included.
Ex: 1,2,3,4,5
EOF
cat /tmp/objects.txt
read -p "Enter selections: "  'CMD'
fi

if [[ $gSDATE == "" ]]; then
    read -p "Enter record start date (format: 2019-12-15T00:00:00) *default is one month prior to current date: "  'gSDATE'
fi

if [[ $gEDATE == "" ]]; then
read -p "Enter record end date (format: 2019-12-15T00:00:00) *default is current date: "  'gEDATE'
fi

if [[ $gSDATE == "" ]] || [[ $gSDATE == "default" ]]; then
    gSDATE=`date -d "$date -1 months" +%Y-%m-%dT%H:%M:%S`
fi

if [[ $gEDATE == "" ]] || [[ $gEDATE == "default" ]]; then
    gEDATE=`date "+%Y-%m-%dT%H:%M:%S"`
fi

echo "$gSDATE" | sed 's/ //g' > /tmp/date.txt

###VALIDATE Date Inputs
if ! egrep -ql "^[0-9]{4}\-[0-9]{2}\-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$" /tmp/date.txt; then
            echo "Starting date $gSDATE not a valid format. Exiting..."
            exit 1
fi

rm -f /tmp/date.txt
echo "$gEDATE" | sed 's/ //g' > /tmp/date.txt

if ! egrep -ql "^[0-9]{4}\-[0-9]{2}\-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$" /tmp/date.txt; then
            echo "Ending date $gEDATE not a valid format. Exiting..."
            exit 1
fi
rm -f /tmp/date.txt

###Build list of mo's to get records on
echo $CMD | sed 's/,/\n/g' > /tmp/args.txt

###Read Mo's to get records for and then get records.
while IFS='' read -r line || [[ -n "$line" ]]; do
    if ! egrep -ql "^$line\." /tmp/objects.txt; then
            log "Selection $line was not valid"
        else
            record=`egrep "^$line\." /tmp/objects.txt | awk -F " " '{print $2}'`
                if [ "$record" == 'faultInst' ] || [ "$record" == 'healthInst' ] || [ "$record" == 'aaaModLR' ]; then
                    if [[ $record == "healthInst" ]]; then
                            sortAtt=updTs
                            SDATE="2010-12-15T00:00:00"
                            EDATE="2050-12-15T00:00:00"
                            getTacRecord
                    fi
                    if [[ $record == "faultInst" ]] || [[ $record == "aaaModLR" ]]; then
                            sortAtt=created
                            SDATE="2010-12-15T00:00:00"
                            EDATE="2050-12-15T00:00:00"
                            getTacRecord
                    fi
                else
                    sortAtt=created
                    SDATE="$gSDATE"
                    EDATE="$gEDATE"
                    getTacRecord
                fi
    fi        
done < '/tmp/args.txt'

rm -f /tmp/objects.txt

###Collect additional MO's that can't be sorted by created attribute
log "Collecting fabricNode objects..."
icurl 'http://localhost:7777/api/class/fabricNode.xml' > fabricNode.xml 2> fabricNode.out
log "Collection of fabricNode completed."
log "Collecting topSystem objects..."
icurl 'http://localhost:7777/api/class/topSystem.xml' > topSystem.xml 2> topSystem.out
log "Collection of topSystem objects completed."
log "Collecting firmwareARunning objects..."
icurl 'http://localhost:7777/api/class/firmwareARunning.xml' > firmwareARunning.xml 2> firmwareARunning.out
log "Collection of firmwareARunning objects completed."


###Tar gzip files for download
log "TacOutput collection completed."
log "Verify files and file sizes at /tmp/$tacDir"
cd /tmp
log "Compressing files..."
tar --force-local -zcf $destDir/TacOutput-"$gSDATE"-to-"$gEDATE".tgz $tacDir
log "Compression completed"
chmod 777 $destDir/TacOutput-"$gSDATE"-to-"$gEDATE".tgz
log2 "Logs available for SCP or SFTP download from $destDir/TacOutput-$gSDATE-to-$gEDATE.tgz"
if [[ $destDir == "/data/techsupport" ]]; then
    log2 "To download through your web browser go to https://<apic address>/files/$apicID/techsupport/TacOutput-$gSDATE-to-$gEDATE.tgz"
fi
log2 ""
log2 "To remove files when done run"
log2 "rm -rf /tmp/$tacDir"
log2 "rm -f $destDir/TacOutput-$gSDATE-to-$gEDATE.tgz"
