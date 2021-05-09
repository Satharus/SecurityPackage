using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        List<List<int>> allPermutations = new List<List<int>>();

        void Permute(int[] nums)
        {
            DoPermute(nums, 0, nums.Length - 1);
        }

        void DoPermute(int[] nums, int start, int end)
        {
            if (start == end)
            {
                allPermutations.Add(new List<int>(nums));
            }
            else
            {
                for (var i = start; i <= end; i++)
                {
                    Swap(ref nums[start], ref nums[i]);
                    DoPermute(nums, start + 1, end);
                    Swap(ref nums[start], ref nums[i]);
                }
            }
        }

        void Swap(ref int a, ref int b)
        {
            var temp = a;
            a = b;
            b = temp;
        }

        public List<int> Analyse(string plainText, string cipherText)
        {
            List<int> key = new List<int>();
            int columns = 2;
            while (columns < cipherText.Length)
            {
                int[] defaultOrder = new int[columns];
                for (int i = 0; i < columns; i++)
                {
                    defaultOrder[i] = i + 1;
                }
                Permute(defaultOrder);
                foreach(var a in allPermutations)
                {
                    key = a;
                    string encryptedPlaintext = Encrypt(plainText, key);

                    if (encryptedPlaintext.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                    {
                        return key;
                    }
                }
                allPermutations.Clear();
                columns++;
            }

            // No valid key found (pretty much impossible, but C# needs a default return path to compile anyway)
            return new List<int> { -1 };
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int columns = key.Count;
            int rows = cipherText.Length / columns;

            if (cipherText.Length % columns != 0) rows++;

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
            for(int i = 0; i < partitionedCipherText.Length; i++)
            {
                if (partitionedCipherText[i] == null)
                {
                    partitionedCipherText[i] = new StringBuilder();
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

            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == '.') plainText.Remove(i, 1);
            }

            return plainText.ToString().ToLower();
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
                        tempCipher[i, k] = '.';
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
                StringBuilder temp = column;
                for (int i = 0; i < temp.Length; i++)
                {
                    if (temp[i] == '.')
                    {
                        temp.Remove(i, 1);
                    }
                }
                cipherText.Append(temp.ToString());
            }

            return cipherText.ToString().ToUpper();
        }
    }
}
