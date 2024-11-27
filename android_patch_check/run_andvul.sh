#!/bin/bash

start_time=`date "+%Y-%m-%d %H:%M:%S"`
start_xxx=`date +%s`

echo "###############"
echo "pull file start!"
echo "###############"
/home/hou/sjtu/pull_file.sh $1 2> /dev/null

echo "###############"
echo "pull file done!"
echo "###############"

echo "###############"
echo "and_vul start!"
echo "###############"

cd /home/hou/sjtu/vulTool/
python3 test.py $1

echo "###############"
echo "and_vul done!"
echo "###############"

end_xxx=`date +%s`
end_time=`date "+%Y-%m-%d %H:%M:%S"`

let time_xxx=$end_xxx-$start_xxx

echo "开始时间: $start_time"
echo "结束时间: $end_time"
echo "累计耗时(s): $time_xxx"
