#!/usr/bin/env bash
fairseq-preprocess \
    --only-source \
    --srcdict data-bin/pretrain_all/dict.txt \
    --trainpref data-src/instbound_oracle/train.data \
    --validpref data-src/instbound_oracle/valid.data \
    --destdir data-bin/instbound_oracle/data \
    --workers 10

fairseq-preprocess \
    --only-source \
    --trainpref data-src/instbound_oracle/train.label \
    --validpref data-src/instbound_oracle/valid.label \
    --destdir data-bin/instbound_oracle/label \
    --workers 10
