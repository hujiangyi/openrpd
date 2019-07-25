#!/bin/sh

rotate_before_reboot()
{
   mkdir -p /rpd/log
   rebootdate=`date`
   echo ${rebootdate} > /tmp/reboot_date.log

   lognum=`ls -l /rpd/log|grep "tar.gz"|wc -l`
   logname=`date '+%F-%T'` 
   if [[ ${lognum} -gt 100 ]]; then
        echo "Log rotate: log file save more than 100 files"
        echo "Log rotate: remove oldest one and rotate again"
        remove_oldest_log=`ls -rt /rpd/log/rpd_reboot_provision_*|head -n 1|xargs rm -rf`
   else
        echo "Log rotate: log file save $lognum files"
        echo "Log rotate: do the rotate for log files"
   fi
   tar czf /rpd/log/rpd_reboot_provision_log_${logname}.tar.gz /tmp/*.log* /tmp/*json 2>/dev/null
   sync
}

rotate_before_reboot
