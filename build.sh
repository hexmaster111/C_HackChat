#!/bin/bash

cc hackchat.c -ggdb -fsanitize=address,leak -ohackchat
