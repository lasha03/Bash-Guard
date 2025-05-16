#!/bin/bash

# Example 1
array1[$(cat /flag)]="value"

# Example 2
read user_input
array2[$user_input]="value"

# Example 3
i=0
array3[$i]="value"

# Example 4
declare -A my_array
echo ${my_array[@]}
