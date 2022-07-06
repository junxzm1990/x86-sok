#!/usr/bin/env bash

MAX_EPOCHS=30
WARMUP_UPDATES=500
LR=1e-05                # Peak LR for polynomial LR scheduler.
NUM_CLASSES=3           # S - start of function, E - end of function, N - in between
MAX_SENTENCES=8        # Batch size.

FUNCBOUND_PATH=checkpoints/instbound_oracle
mkdir -p $FUNCBOUND_PATH
rm -f $FUNCBOUND_PATH/checkpoint_best.pt

# finetune on pretrained weights
cp checkpoints/pretrain_all/checkpoint_best.pt $FUNCBOUND_PATH/

CUDA_VISIBLE_DEVICES=0 python train.py data-bin/instbound_oracle \
    --max-positions 512 \
    --max-sentences $MAX_SENTENCES \
    --user-dir finetune_tasks \
    --task funcbound \
    --reset-optimizer --reset-dataloader --reset-meters \
    --required-batch-size-multiple 1 \
    --arch roberta_base \
    --criterion funcbound \
    --num-classes $NUM_CLASSES \
    --dropout 0.1 --attention-dropout 0.1 \
    --weight-decay 0.1 --optimizer adam --adam-betas "(0.9, 0.98)" --adam-eps 1e-06 \
    --clip-norm 0.0 \
    --lr-scheduler polynomial_decay --lr $LR --max-epoch $MAX_EPOCHS --warmup-updates $WARMUP_UPDATES \
    --best-checkpoint-metric accuracy --maximize-best-checkpoint-metric \
    --find-unused-parameters \
    --no-epoch-checkpoints --update-freq 4 --log-format=json --log-interval 10 \
    --save-dir $FUNCBOUND_PATH \
    --restore-file $FUNCBOUND_PATH/checkpoint_best.pt | tee result/funcbound
