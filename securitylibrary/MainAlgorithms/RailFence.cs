using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            string ret;
            int key = 0;
            for (int i = 1; i < plainText.Length; i++)
            {
                ret = Encrypt(plainText, i);
                if (ret == cipherText)
                {
                    key = i; break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {

            float keyy = (float)key;
            float val = cipherText.Length / keyy;
            double plaintext_len = Math.Ceiling(val);
            int len = Convert.ToInt32(plaintext_len);
            string ret = "";
            List<string> plain = new List<string>();
            int count = 0;
            for (int i = 0; i < len; i++)
            {
                count = i;
                for (int j = 0; j < key; j++)
                {
                    if (count < cipherText.Length)
                    {
                        ret += cipherText[count];
                        count += len;
                    }

                }

            }
            return ret.ToLower();
        }

        public string Encrypt(string plainText, int key)
        {
            List<string> ciphertext = new List<string>();

            int j = 0;
            int cont = 0;
            for (int i = 0; i < key; i++)
            {
                string val = "";
                j = cont;
                for (; j < plainText.Length; j += key)
                {
                    val += plainText[j];
                }
                ciphertext.Add(val);
                cont++;

            }
            string ret = "";
            for (int i = 0; i < key; i++)
                ret += ciphertext[i];
            return ret.ToUpper();

        }
    }
}
