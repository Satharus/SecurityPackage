using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        static string alphabets = "abcdefghiklmnopqrstuvwxyz";
        public string Decrypt(string cipherText, string key)
        {
            //string cipherText = "";

            //// Generate key square
            //key = key.Replace('j','i');
            //string oldKey = key;
            //key="";
            //for(int i=0 ; i<oldKey.Length ; i++){
            //    if(!key.Contains(oldKey[i])){
            //        key+=oldKey[i];
            //    }
            //}
            //char[,] keyArray=new char[5, 5];
            //int keyIndex = 0;
            //int alphabetsIndex = 0;
            //for(int i=0 ; i<5; i++){
            //    for(int j=0 ; j<5 ; j++){
            //        if (keyIndex < key.Length){
            //            keyArray[i,j]=key[keyIndex];
            //            keyIndex++;
            //        }
            //        else{
            //            while(alphabetsIndex<25){
            //                if (!key.Contains(alphabets[alphabetsIndex])){
            //                    keyArray[i,j] = alphabets[alphabetsIndex];
            //                    alphabetsIndex++;
            //                    break;
            //                }
            //                alphabetsIndex++;
            //            }
            //        }
            //    }
            //}

            //// Encrypt
            //if(!(plainText.Length%2==0)){
            //    plainText+='x';
            //}
            //for(int i=0 ; i<plainText.Length-1 ; i+=2){
            //    int r1=0,c1=0,r2=0,c2=0;
            //    for(int j=0 ; j<5 ; j++){
            //        for(int k=0 ; k<5 ; k++){
            //            if(plainText[i]==keyArray[j,k]){
            //                r1=j;
            //                c1=k;
            //            }
            //            if(plainText[i+1]==keyArray[j,k]){
            //                r2=j;
            //                c2=k;
            //            }
            //        }
            //    }
            //    if(r1 == r2){
            //        if(c1+1>4){
            //            cipherText+=keyArray[r1,0];
            //        }
            //        else{
            //            cipherText+=keyArray[r1, c1+1];
            //        }

            //        if(c2+1>4){
            //            cipherText+=keyArray[r2,0];
            //        }
            //        else{
            //            cipherText+=keyArray[r2, c2+1];
            //        }
            //    }

            //    else if(c1 == c2){
            //        if(r1+1>4){
            //            cipherText+=keyArray[0,c1];
            //        }
            //        else{
            //            cipherText+=keyArray[r1+1, c1];
            //        }

            //        if(r2+1>4){
            //            cipherText+=keyArray[0,c2];
            //        }
            //        else{
            //            cipherText+=keyArray[r2+1, c2];
            //        }
            //    }
            //    else{
            //        cipherText+=keyArray[r1,c2];
            //        cipherText+=keyArray[r2,c1];
            //    }
            //}

            // throw new NotImplementedException();
            return cipherText;
        }

        public string Encrypt(string plainText, string key)
        {
            //string plainText = "";

            //// Generate key square
            //key = key.Replace('j','i');
            //string oldKey = key;
            //key="";
            //for(int i=0 ; i<oldKey.Length ; i++){
            //    if(!key.Contains(oldKey[i])){
            //        key+=oldKey[i];
            //    }
            //}
            //char[,] keyArray=new char[5, 5];
            //int keyIndex = 0;
            //int alphabetsIndex = 0;
            //for(int i=0 ; i<5; i++){
            //    for(int j=0 ; j<5 ; j++){
            //        if (keyIndex < key.Length){
            //            keyArray[i,j]=key[keyIndex];
            //            keyIndex++;
            //        }
            //        else{
            //            while(alphabetsIndex<25){
            //                if (!key.Contains(alphabets[alphabetsIndex])){
            //                    keyArray[i,j] = alphabets[alphabetsIndex];
            //                    alphabetsIndex++;
            //                    break;
            //                }
            //                alphabetsIndex++;
            //            }
            //        }
            //    }
            //}

            //// Decrypt
            //for(int i=0 ; i<cipherText.Length-1 ; i+=2){
            //    int r1=0,c1=0,r2=0,c2=0;
            //    for(int j=0 ; j<5 ; j++){
            //        for(int k=0 ; k<5 ; k++){
            //            if(cipherText[i]==keyArray[j,k]){
            //                r1=j;
            //                c1=k;
            //            }
            //            if(cipherText[i+1]==keyArray[j,k]){
            //                r2=j;
            //                c2=k;
            //            }
            //        }
            //    }
            //    if(r1 == r2){
            //        if(c1-1<0){
            //            plainText+=keyArray[r1,4];
            //        }
            //        else{
            //            plainText+=keyArray[r1, c1-1];
            //        }

            //        if(c2-1<0){
            //            plainText+=keyArray[r2,4];
            //        }
            //        else{
            //            plainText+=keyArray[r2, c2-1];
            //        }
            //    }

            //    else if(c1 == c2){
            //        if(r1-1<0){
            //            plainText+=keyArray[4,c1];
            //        }
            //        else{
            //            plainText+=keyArray[r1-1, c1];
            //        }

            //        if(r2-1<0){
            //            plainText+=keyArray[4,c2];
            //        }
            //        else{
            //            plainText+=keyArray[r2-1, c2];
            //        }
            //    }
            //    else{
            //        plainText+=keyArray[r1,c2];
            //        plainText+=keyArray[r2,c1];
            //    }
            //}

            // throw new NotImplementedException();
            return plainText;
        }
    }
}
