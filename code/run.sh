#!/bin/bash

export CUDA_VISIBLE_DEVICES=5

#d2
#labels=reddit,facebook,NeteaseMusic,twitter,qqmail,instagram,weibo,iqiyi,
#labels+=imdb,TED,douban,amazon,youtube,JD,youku,baidu,google,tieba,taobao,bing

#d1
labels=MS-Exchange,facebook,kugou,sinauc,thunder,weibo,aimchat,gmail,mssql,skype,tudou,yahoomail,amazon,google,netflix,sohu,twitter,youku,baidu,itunes,pplive,spotify,vimeo,youtube,cloudmusic,jd,qq,taobao,voipbuster


output_dir=../save/teacher

python run.py \
    --do_train \
    --data_dir ../data \
    --dataset d1 \
    --output_dir ${output_dir} \
    --epochs 50 --labels $labels \
    --batch_size 512 --gpu 0 --gamma 1 \
    --model EBSNN_LSTM --segment_len 16 \
    --embedding_dim 128 \
    --dropout 0.5 \
    --no_bidirectional \
    --log_filename ${output_dir}/plog.log \
    --logging_steps 50 \
    --shuffle
