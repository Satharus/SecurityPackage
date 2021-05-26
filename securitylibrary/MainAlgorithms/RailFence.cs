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
            int key = 0;
            string ans = "";
            for (int i = 1; i < plainText.Length; i++)
            {
                ans = Decrypt(cipherText, i);
                if (plainText == ans)
                {
                    key = i;
                    break;
                }
            }
            return key;

        }

        public string Decrypt(string cipherText, int key)
        {
            char[,] decrypted = new char[100, 100];

            float len = Convert.ToSingle(cipherText.Length);
            len /= key;
            int rounded_f = (int)(len + 0.5f);

            int idx = 0;
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < rounded_f; j++)
                {
                    if (idx == cipherText.Length) break;
                    decrypted[i, j] = cipherText[idx];
                    idx++;
                }
            }

            string ans2 = "";
            for (int i = 0; i < rounded_f; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    ans2 += decrypted[j, i];
                }
            }
            return ans2.ToLower();

        }

        public string Encrypt(string plainText, int key)
        {
            int cnt = 0;
            float cols = Convert.ToSingle(plainText.Length);
            int rounded_f = (int)(cols + 0.5f);
            char[,] arr = new char[100, 100];

            for (int i = 0; i < rounded_f; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (cnt == plainText.Length) break;
                    arr[j, i] = plainText[cnt];
                    cnt++;
                }
            }
            string ans = "";
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    ans += arr[i, j];
                }

            }




            return ans.ToUpper();

        }
    }
}
