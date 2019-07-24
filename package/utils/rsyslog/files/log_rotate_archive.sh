#!/bin/sh
# rotate into tar.gz archive
logname=${1}

rotate()
{
   logtime=`date '+%F-%T'` 
   mkdir -p /rpd/log/${logname}
   tar czf /rpd/log/${logname}/rpd_${logname}_${logtime}.tar.gz /tmp/${logname} 2>/dev/null
   rm /tmp/${logname}
}

rotate
