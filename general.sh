#!/bin/bash

function ReplaceSpecialCharacters {
   #specstr='.[*]^${}\/+?|()'
   specstr='/'
   ReplaceSpecialCharacters=""
   #echo $1
   CharLen=${#1}
   for (( charnum=0; charnum < $CharLen; charnum++))  
   do
        char=${1:charnum:1}
        #echo $char
        special=0         
        SCharLen=${#specstr}
        for (( scharnum=0; scharnum < $SCharLen; scharnum++))
        do
            schar=${specstr:scharnum:1}
            #echo $("$char"="$schar")
            if [ "$char" = "$schar" ]
            
            then
                special=1
                #echo "Special!"
            fi
            
        done
        if [ $special = 0 ]
        then            
            ReplaceSpecialCharacters=$ReplaceSpecialCharacters$char
        else
            #echo "special "$char 
            ReplaceSpecialCharacters=$ReplaceSpecialCharacters"\\"$char
        fi
   done
}
function RemoveEmptyStrings {
    sed -i  '/^$/d' $1
}
function AddNewString {
    echo  "$1" >> $2
}
function RemoveStringsByNumbers {
    if [ "$2" != "" ]
    then
        /bin/sed -i -e "$1" $2
    fi
}
function CheckConfigFile {
    #$1 Command
    #$2 File
    #$3 ResultFile
    #$4 Action if correct
    #echo "sudo sh -c '$1'"
    if [ -f $2 ]; then
        echo "file $2 - exist!"
    else
        echo "file $2 - NOT exist!!!!"
    fi
    if [ "$3" = "" ]; then
        sudo sh -c "$1"
        correct=false
    else
        sudo sh -c "$1" &> $3
        #echo "sudo sh -c \"$1\" &> $3"
        if [ $(grep '' $3 | wc -l) = 0 ]; then
            echo "$2 is correct!"
            correct=true	
        else
            echo "$2 is incorrect!"
            cat $3
            correct=false
        fi        
    fi
    if [ $correct = true ]; then
        sudo sh -c "$4"
        echo "sudo sh -c \"$4\""
    fi
}
function AddOrReplaceParamInFile {
    #$1 - Param name
    #$2 - Param new value
    #$3 - File
    #$4 - Level
    #echo "/bin/grep -e "$1" -c $3"
    if [ -f "$3" ]
    then
        #echo ""
        #echo "==================================="
        #echo "level="$4
        if [ "$4" != "" ]
        then
            num=$(( $4 * 5 ))
            #echo "num="$num
            level=`for (( i=1; i < $num; i++)); do echo -n " "; done`
        else
            level=""
        fi
    
        echo - $level$1$2

        ReplaceSpecialCharacters "$1"
        ReplParam=$ReplaceSpecialCharacters
        ReplaceSpecialCharacters "$2"
        ReplVal=$ReplaceSpecialCharacters

        #echo $ReplaceSpecialCharacters
        ParamCount=$(cat $3 | grep -e "$ReplParam" -c)
        
        if [ "$ReplVal" != "" ]
        then
            NewParamStringRepl="$level$ReplParam$ReplVal"
            NewParamString="$level$1$2"
        else
            NewParamStringRepl="$level$ReplParam"
            NewParamString="$level$1"
        fi
        #echo  $NewParamStringRepl
        ParamStringNums=$(cat $3 |sed -n "/$ReplParam/{=}") #grep -e $ReplParam -n $3) 
        #echo "ParamStringNums="$ParamStringNums  
        #Secho "ParamCount="$ParamCount  
        case $ParamCount in
            0)
                #echo "New parameter"
                AddNewString "$NewParamString" $3
                #echo  "$NewParamString" >> $3
                #echo  $NewParamStringRepl            
                ;;
            1)
                #echo "Existing parameter"
                #echo  $NewParamStringRepl
                #echo "s/.*$ReplParam.*/$NewParamStringRepl/"
                #/bin/sed -i -e  "s/.*$ReplParam.*/$NewParamStringRepl/" $3
                strlist=$ParamStringNums"d"
                #echo "strlist="$strlist
                RemoveStringsByNumbers $strlist $3
                #/bin/sed -i -e "$strlist" $3
                AddNewString "$NewParamString" $3
                #echo  "$NewParamString" >> $3
                ;;
            *)
                #echo "Multi parameter"    
                strlist=""
                cnt=0
                for var in $ParamStringNums
                do
                        LtrimStr=$(sed -n $var"p" $3 | sed -e "s/^[ \t]*//")                    
                        LtrimParam=$(echo $ReplParam | sed -e "s/^[ \t]*//") 
                        RtrimParam=$(echo $ReplParam | sed -e "s/[ \t]*$//") 
                        LeftSideStr=$(echo $LtrimStr | sed -e "s/$LtrimParam.*//")
                        RightSideStr=$(echo $LtrimStr | sed -e "s/*.$RtrimParam//")
                        #echo $LtrimStr
                        #echo $LeftSideStr ${#LeftSideStr}
                        LeftSideStrLen=${#LeftSideStr} 
                        RightSideStrLen=${#RightSideStr} 
                        #echo $var
                        if [ $LeftSideStrLen = 0 ] #&& [ $RightSideStrLen = 0 ]
                        then
                            if [ "$strlist" != "" ]
                            then
                                strlist=$strlist";"$var"d"
                            else
                                strlist=$var"d"
                                str=$var
                            fi
                            cnt=$(( $cnt + 1 ))
                        fi
                done          
                #echo "strlist="$strlist
                # echo "cnt="$cnt
                # if [ $cnt = 1 ]
                # then
                #     #echo "cnt="$cnt
                #     #echo $LtrimStr
                #     #echo "$str s/.*$ReplParam.*/$NewParamStringRepl/"
                #     /bin/sed -i -e  "$str s/.*$ReplParam.*/$NewParamStringRepl/" $3
                # else
                #     #echo "cnt="$cnt
                #     #echo $LtrimStr
                #     /bin/sed -i -e "$strlist" $3
                #     echo  "Add new param: "$NewParamStringRepl
                #     echo  "$NewParamStringRepl" >> $3
                # fi
                RemoveStringsByNumbers $strlist $3
                #/bin/sed -i -e "$strlist" $3
                    #echo  "Add new param: "$NewParamString
                    AddNewString "$NewParamString" $3
                    #echo  "$NewParamString" >> $3
                #echo $ReplParam                    
                ;;
        esac
    fi
}