#!/bin/zsh
# A script for checking possible vulnerabilitites in a given org on GitHub
# usage: ./vulnerbailities.sh <name_of_org>
# requirements: GitHub CLI and Scorecard
if [ -z "$1" ]; then
    echo "Need to provide the name of an organization"
    exit -1
fi
repos=($(gh repo list $1 --limit 150 --json name --jq '.[].name'))
typeset -A hash
echo 'Found '${#repos[@]}'' $1 'repos'
critical_count_tot=0
for repo in $repos; do
    echo '\nChecking '$repo
    vulnerabilities=($(scorecard --checks=Vulnerabilities --show-details --format=json --repo=github.com/$1/$repo | jq 'select(.checks.[].details != null).checks.[].details.[]' | grep -oE -e "GHSA-[^ \"]*"))
    critical_count=0
    for vulnerability in $vulnerabilities; do
        json=($(gh api --method GET -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" /advisories -F ghsa_id="$vulnerability" --jq ".[].severity,.[].cvss.score,.[].html_url"))
        severity=$json[1]
        if [[ $severity == "critical" ]] 
        then
            critical_count=$((critical_count+1))            
            critical_count_tot=$((critical_count_tot+1))
            score=$json[2]
            url=$json[3]
            echo $url' '$severity' '$score
            if [[ -v hash[$url] ]]; then
                num=${hash[$url]}
                hash[$url]=$((num+1))
            else
                hash[$url]=1
            fi
        fi
    done
    echo 'Number of critical vulnerabilities in '$repo': '$critical_count
done
for key val in "${(@kv)hash}"; do
    echo "$key: $val occurences"
done
echo '\nNumber of total critical vulnerabilities : '$critical_count_tot
