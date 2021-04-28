using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {

        public string Decrypt(string cipherText, string key)
        {
            string val = "";
            return val;
        }

        static public string alphapitics = "abcdefghijklmnopqrstuvwxyz";
        static public int[] char_checked = new int[26];
        static public void mem()
        {
            for (int i = 0; i < 25; i++)
                char_checked[i] = 0;
        }
        
        static public void print_array(char[,] arr_key)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                    Console.Write(arr_key[i, j]);
                Console.Write("\n");
            }
        }
        static public char[,] mem_2d(char[,] arr_key, int i , int j) { 
            for (int k = 0; k < i; k++)
            {
                for (int x = 0; x < j; x++)
                    arr_key[k, x] = '\0';

            }
            return arr_key;
        }
        static public char[,] Generate_array(char[,] arr_key, string key)
        {
            mem();
            arr_key = mem_2d(arr_key, 5, 5);
            int found;
            int index_of_key = 0;
            int index_of_alphabitics = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
<<<<<<< HEAD
                { 
                    for (int k = 0; k < 5; k++)
=======
                {
                    found = 0;
                    for (int k = index_of_key; k < key.Length; k++)
>>>>>>> d0f73dacbaf6f8ecef62ccc05246b4814efaa45a
                    {
                        
                        if (char_checked[((key[k] - 97) % alphapitics.Length)] == 0)
                        {
                            arr_key[i, j] = key[k];
                            char_checked[((key[k] - 97) % alphapitics.Length)] = 1;
                            found = 1;

                        }
                        if (found == 1)
                            break;
                    }

                    if (found == 0)
                    {
                        for (int k = index_of_alphabitics; k < alphapitics.Length; k++)
                        {


                            if (char_checked[((alphapitics[k] - 97) % alphapitics.Length)] == 0)
                            {
                                if (alphapitics[k] != 'j')
                                {

                                    arr_key[i, j] = (char)(k + 97);
                                    char_checked[((alphapitics[k] - 97) % alphapitics.Length)] = 1;
                                    index_of_alphabitics++;
                                    break;
                                }
                                if (alphapitics[k] == 'j')
                                    index_of_alphabitics++;

                            }
                        }
                    }


                    index_of_key++;
                }
            }
            return arr_key;
        }
        static public string Handle_duplicate(string value)
        {
            for (int i = 0; i < value.Length - 1; i += 2)
            {
                if (value[i] == value[i + 1])
                {
                    value = value.Substring(0, i + 1) + 'x' + value.Substring(i + 1);
                }

            }
            if (value.Length % 2 == 1) value += 'x';
            return value;
        }
        static public int[] getPosition(char[,] arr_key, char first, char second)
        {
            int[] positions = new int[4];
            for (int i = 0; i < 4; i++)
            {
                positions[i]= 0;
            }
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (arr_key[i, j] == first)
                    {
                        positions[0] = i; positions[1] = j;
                    }
                    if (arr_key[i, j] == second)
                    {
                        positions[2] = i; positions[3] = j;
                    }
                }
            }
            return positions;
        }
        
        public string Encrypt(string plainText, string key)
        {
            char[,] arr_key = new char[5, 5];
            
            string val = Handle_duplicate(plainText);
            string ret = "";
            int[] positions = new int[4];
            // char_row1 , char_col1 ,char_row2, char_col2
            mem_2d(arr_key, 5, 5);
            arr_key = Generate_array(arr_key, key);
            for (int i = 0; i < val.Length; i += 2)
            {

                char encrypt_char1 = '\0';
                char encrypt_char2 = '\0';

                positions = getPosition(arr_key, val[i], val[i + 1]);
                if (positions[0] == positions[2])
                {
                    encrypt_char1 = arr_key[positions[0], (positions[1] + 1) % 5];
                    encrypt_char2 = arr_key[positions[2], (positions[3] + 1) % 5];

                    //same row
                }
                else if (positions[1] == positions[3])
                {
                    encrypt_char1 = arr_key[(positions[0] + 1) % 5, positions[1]];
                    encrypt_char2 = arr_key[(positions[2] + 1) % 5, positions[3]];
                    //same column
                }
                else // if (positions[0] != positions[2] && positions[1] != positions[3])
                {
                    encrypt_char1 = arr_key[(positions[0]), (positions[3])];
                    encrypt_char2 = arr_key[(positions[2]), (positions[1])];
                    //diagonal
                }


                ret += encrypt_char1;
                ret += encrypt_char2;
            }
            ret = ret.ToUpper();
            return ret;
        }
    }
}
