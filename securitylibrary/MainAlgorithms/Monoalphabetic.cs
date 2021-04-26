using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            StringBuilder key = new StringBuilder("**************************");
            bool[] charExists = new bool[26];
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = plainText[i] - 'a';
                char cipherCharacter = cipherText[i];
                key[index] = cipherCharacter;
                charExists[cipherCharacter - 'A'] = true;
            }

            //Replace the rest of the characters in order to have a possible key which includes the whole alphabet
            for (int i = 0; i < key.Length; i++)
            {
                if (key[i] == '*')
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (!charExists[j])
                        {
                            key[i] = (char)('A' + j);
                            charExists[j] = true;
                            break;
                        }
                    }
                }
            }

            return key.ToString().ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            StringBuilder decryptedText = new StringBuilder(cipherText);

            for (int i = 0; i < cipherText.Length; i++)
            {
                char currentCipherChar = cipherText[i].ToString().ToLower()[0];
                decryptedText[i] = (char) ('a' + key.IndexOf(currentCipherChar));
            }

            return decryptedText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            StringBuilder encryptedText = new StringBuilder(plainText);

            for (int i = 0; i < plainText.Length; i++)
            {
                encryptedText[i] = key[encryptedText[i] - 'a'];
            }

            return encryptedText.ToString().ToUpper();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            throw new NotImplementedException();
        }
    }
}
