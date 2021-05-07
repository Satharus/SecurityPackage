using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int columns = key.Count;
            int rows = plainText.Length / columns;

            if (plainText.Length % columns != 0) rows++;


            char[,] tempCipher = new char[rows, columns];
            StringBuilder cipherText = new StringBuilder();

            for (int i = 0; i < rows; i++)
            {
                for (int k = 0; k < columns; k++)
                {

                    int index = (i * columns) + k;
                    if (index < plainText.Length)
                    {
                        tempCipher[i, k] = plainText[index];
                    }
                    else
                    {
                        tempCipher[i, k] = 'x';
                    }
                }
            }

            StringBuilder[] cipherTextOrdered = new StringBuilder[columns];

            int j = 0;
            foreach (int keyColumn in key)
            {
                cipherTextOrdered[keyColumn - 1] = new StringBuilder();
                for (int i = 0; i < rows; i++)
                {
                    cipherTextOrdered[keyColumn-1].Append(tempCipher[i, j]);
                }
                j++;
            }

            foreach (StringBuilder column in cipherTextOrdered)
            {
                cipherText.Append(column.ToString());
            }

            return cipherText.ToString().ToUpper();
        }
    }
}
