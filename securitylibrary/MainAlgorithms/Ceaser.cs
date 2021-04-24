using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            StringBuilder encryptedText = new StringBuilder(plainText);
            for (int i = 0; i < plainText.Length; i++)
            {
                encryptedText[i] += (char)key;
                if (!(encryptedText[i] >= 'A' && encryptedText[i] <= 'Z') &&
                    !(encryptedText[i] >= 'a' && encryptedText[i] <= 'z'))
                {
                    encryptedText[i] -= (char)26;
                }
            }
            return encryptedText.ToString();
        }

        public string Decrypt(string cipherText, int key)
        {
            StringBuilder decryptedText = new StringBuilder(cipherText);
            for (int i = 0; i < cipherText.Length; i++)
            {
                decryptedText[i] -= (char)key;
                if (!(decryptedText[i] >= 'A' && decryptedText[i] <= 'Z') &&
                    !(decryptedText[i] >= 'a' && decryptedText[i] <= 'z'))
                {
                    decryptedText[i] += (char)26;
                }
            }
            return decryptedText.ToString();
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int key = (int)cipherText[0] - plainText[0];

            if (key >= 26) key -= 26;
            else if (key < 0) key += 26;

            return Math.Abs(key);
        }
    }
}
