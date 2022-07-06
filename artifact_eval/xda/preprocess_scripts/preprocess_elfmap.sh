#!/usr/bin/env bash
fairseq-preprocess \
    --only-source \
    --srcdict data-bin/pretrain_all/dict.txt \
    --trainpref data-src/instbound_elfmap/train.data \
    --validpref data-src/instbound_elfmap/valid.data \
    --destdir data-bin/instbound_elfmap/data \
    --workers 10

fairseq-preprocess \
    --only-source \
    --trainpref data-src/instbound_elfmap/train.label \
    --validpref data-src/instbound_elfmap/valid.label \
    --destdir data-bin/instbound_elfmap/label \
    --workers 10
