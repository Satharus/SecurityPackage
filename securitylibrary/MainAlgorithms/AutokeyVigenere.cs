using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        char[,] alphabetMatrix = new char[26, 26];

        public AutokeyVigenere()
        {
            char start = 'A';
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    if ((start + j) > 'Z')
                    {
                        alphabetMatrix[i, j] = (char)((start + j) - 'Z' + 'A' - 1);
                    }
                    else
                    {
                        alphabetMatrix[i, j] = (char)(start + j);
                    }
                }
                start++;
            }
        }

        public string Analyse(string plainText, string cipherText)
        {
            StringBuilder keyStream = new StringBuilder();

            for (int i = 0; i < plainText.Length; i++)
            {
                char keyChar = '.';
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == this.alphabetMatrix[j, plainText[i] - 'a'])
                    {
                        keyChar = (char)('a' + j);
                    }
                }
                keyStream.Append(keyChar);
            }

            int max = -1;
            for (int i = 0; i < plainText.Length; i++)
            {
                int idx = keyStream.ToString().IndexOf(plainText.Substring(0, i));
                if ( idx > max)
                {
                    max = idx;
                }
            }

            return keyStream.ToString().ToLower().Substring(0, max);
        }

        public string Decrypt(string cipherText, string key)
        {
            StringBuilder keyStream = new StringBuilder();
            StringBuilder plainText = new StringBuilder();
            keyStream.Append(key);
            int k = 0;
            while (keyStream.Length < cipherText.Length)
            {

                char keystreamChar = '.';
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[k] == this.alphabetMatrix[keyStream[k] - 'a', j])
                    {
                        keystreamChar = (char)('a' + j);
                    }
                }
                keyStream.Append(keystreamChar);
                k++;
            }

            
            for (int i = 0; i < cipherText.Length; i++)
            {
                char plainChar = '.';
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == this.alphabetMatrix[keyStream[i] - 'a', j])
                    {
                        plainChar = (char)('a' + j);
                    }
                }
                plainText.Append(plainChar);
            }

            return plainText.ToString().ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            StringBuilder keyStream = new StringBuilder();
            StringBuilder cipherText = new StringBuilder();
            keyStream.Append(key);
            while (keyStream.Length < plainText.Length)
            {
                keyStream.Append(plainText);
            }

            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText.Append(this.alphabetMatrix[plainText[i] - 'a', keyStream[i] - 'a']);
            }

            return cipherText.ToString().ToUpper();
        }
    }
}
