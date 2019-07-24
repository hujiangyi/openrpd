#!/bin/sh
do_rotate_clean()
{
   # more than 10 rotation file,should do some  rotate clean
   lognum=`ls $1/rpd_*.tar.gz|wc -l`
   while [[ $lognum -gt 10 ]]
   do
       logger -p local7.info "Clean Log Rotate: delete one oldest $1 one archive"
       ls -rt $1/rpd_*.tar.gz|head -n 1|xargs rm -rf
       lognum=`ls $1/rpd_*.tar.gz|wc -l`
   done 
}

rpd_log_rotate_clean()
{
   RPD_LOG_FOLDER="/rpd/log/*"
   for log in $RPD_LOG_FOLDER 
   do
        if [ -d "$log" ]
        then
            echo "clean up $log"
            do_rotate_clean $log
        fi
   done
}

rpd_log_rotate_clean
