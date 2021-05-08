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
            int columns = key.Count;
            int rows = cipherText.Length / columns;

            if (cipherText.Length % columns != 0) rows++;

            char[,] tempCipher = new char[rows, columns];

            StringBuilder[] partitionedCipherText = new StringBuilder[columns];

            int j = 0;
            for (int i = 0; i < cipherText.Length; i+=rows)
            {
                partitionedCipherText[j] = new StringBuilder();
                if (i + rows < cipherText.Length)
                {
                    partitionedCipherText[j].Append(cipherText.Substring(i, rows));
                    j++;
                }
                else
                {
                    partitionedCipherText[j].Append(cipherText.Substring(i));
                    j++;
                }
            }

            Dictionary<int, int> swaps = new Dictionary<int, int>();
            for (int i = 0; i < key.Count; i++)
            {
                swaps.Add(key[i] - 1, i);
            }

            StringBuilder[] sortedCipherText = new StringBuilder[columns];
            foreach (var swap in swaps)
            {
                sortedCipherText[swap.Value] = partitionedCipherText[swap.Key];
            }

            StringBuilder plainText = new StringBuilder();
            for(int i = 0; i < rows; i++)
            {
                for (int k = 0; k < columns; k++)
                {
                    if (i < sortedCipherText[k].Length)
                    {
                        plainText.Append(sortedCipherText[k][i]);
                    }
                }
            }

            return plainText.ToString();
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
