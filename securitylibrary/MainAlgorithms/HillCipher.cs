using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        private int findB(int det)
        {
            int i = 1;
            while (true)
            {
                if (((i % 26) * (det % 26)) % 26 == 1)
                {
                    break;
                }
                i++;
            }
            return i;
        }
        private int calcSqrt(int nmbr)
        {
            if (nmbr == 0)
            {
                return 0;
            }
            else if (nmbr == 1)
            {
                return 1;
            }
            int i;
            for (i = 0; i < nmbr / 2; i++)
            {
                if (i * i == nmbr)
                {
                    break;
                }
            }
            return i;
        }
        private List<List<int>> makeKeyMatrix(List<int> key, int m)
        {
            List<List<int>> matrix = new List<List<int>>();
            int k = 0;
            for (int i = 0; i < m; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    tmp.Add(key[k]);
                    k++;
                }
                matrix.Add(tmp);
            }
            return matrix;
        }
        private List<List<int>> makeTextMatrix(List<int> text, int m)
        {
            List<List<int>> matrix = new List<List<int>>();
            int k = 0;
            for (int i = 0; i < text.Count / m; i++)
            {
                List<int> tmp = new List<int>();
                for (int j = 0; j < m; j++)
                {
                    tmp.Add(text[k]);
                    k++;
                }
                matrix.Add(tmp);
            }
            return matrix;
        }
        private List<int> multiplyMatrix(List<List<int>> key, List<int> plainText, int m)
        {
            List<int> res = new List<int>();
            for (int i = 0; i < m; i++)
            {
                int tmp = 0;
                for (int j = 0; j < m; j++)
                {
                    tmp += key[i][j] * plainText[j];
                }
                tmp = tmp % 26;
                while (tmp < 0)
                {
                    tmp += 26;
                }
                res.Add(tmp);
            }
            return res;
        }
        private int calcDeterminant(List<List<int>> matrix, int m)
        {
            if (m == 2)
            {
                return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
            }
            int det = 0;
            for (int k = 0; k < m; k++)
            {
                List<List<int>> tmp = new List<List<int>>();
                for (int i = 0; i < m; i++)
                {
                    List<int> tmp2 = new List<int>();
                    for (int j = 0; j < m; j++)
                    {
                        if (i != 0 && j != k)
                        {
                            tmp2.Add(matrix[i][j]);
                        }
                    }
                    if (tmp2.Count != 0)
                    {
                        tmp.Add(tmp2);
                    }
                }
                if (k % 2 == 0)
                {
                    det += matrix[0][k] * calcDeterminant(tmp, m - 1);
                }
                else
                {
                    det -= matrix[0][k] * calcDeterminant(tmp, m - 1);
                }
            }
            return det;
        }
        private List<List<int>> makeMinorsMatrix(List<List<int>> matrix, int m)
        {
            List<List<int>> res = new List<List<int>>();
            for (int k = 0; k < m; k++)
            {
                List<int> tmpRes = new List<int>();
                for (int l = 0; l < m; l++)
                {
                    List<List<int>> tmp = new List<List<int>>();
                    for (int i = 0; i < m; i++)
                    {
                        List<int> tmp2 = new List<int>();
                        for (int j = 0; j < m; j++)
                        {
                            if (i != k && j != l)
                            {
                                tmp2.Add(matrix[i][j]);
                            }
                        }
                        if (tmp2.Count != 0)
                        {
                            tmp.Add(tmp2);
                        }
                    }
                    int minor = calcDeterminant(tmp, m - 1);
                    tmpRes.Add(minor);
                }
                res.Add(tmpRes);
            }
            return res;
        }
        private List<List<int>> makeCofactorsMatrix(List<List<int>> matrix, int m)
        {
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    if ((i + j) % 2 != 0)
                    {
                        matrix[i][j] *= -1;
                    }
                }
            }
            return matrix;
        }
        private List<List<int>> makeAdjointMatrix (List<List<int>> matrix, int m)
        {
            for (int i = 0; i < m; i++)
            {
                for (int j = i+1; j < m; j++)
                {
                    int tmp = matrix[i][j];
                    matrix[i][j] = matrix[j][i];
                    matrix[j][i] = tmp;
                }
            }
            return matrix;
        }
        private List<List<int>> inverseMatrix(List<List<int>> matrix, int m)
        {
            int det = calcDeterminant(matrix, m);
            while(det < 0){
                det += 26;
            }
            det = findB(det);
            if (m == 2)
            {
                int tmp = matrix[0][0] * det;
                matrix[0][0] = matrix[1][1] * det;
                matrix[1][1] = tmp;

                matrix[0][1] *= (-1 * det);
                matrix[1][0] *= (-1 * det);
                return matrix;
            }
            matrix = makeMinorsMatrix(matrix, m);
            matrix = makeCofactorsMatrix(matrix, m);
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    matrix[i][j] *= det;
                }
            }
            matrix = makeAdjointMatrix(matrix, m);
            return matrix;
        }
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plainText = new List<int>();
            int m = calcSqrt(key.Count);
            List<List<int>> keyMatrix = makeKeyMatrix(key, m);
            List<List<int>> cipherTextMatrix = makeTextMatrix(cipherText, m);
            keyMatrix = inverseMatrix(keyMatrix, m);
            for (int i = 0; i < cipherText.Count / m; i++)
            {
                List<int> tmp = multiplyMatrix(keyMatrix, cipherTextMatrix[i], m);
                for (int j = 0; j < m; j++)
                {
                    plainText.Add(tmp[j]);
                }
            }
            return plainText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherText = new List<int>();
            int m = calcSqrt(key.Count);
            List<List<int>> keyMatrix = makeKeyMatrix(key, m);
            List<List<int>> plainTextMatrix = makeTextMatrix(plainText, m);
            for (int i = 0; i < plainText.Count / m; i++)
            {
                List<int> tmp = multiplyMatrix(keyMatrix, plainTextMatrix[i], m);
                for (int j = 0; j < m; j++)
                {
                    cipherText.Add(tmp[j]);
                }
            }
            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }

    }
}
