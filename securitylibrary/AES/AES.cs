using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        byte[,] sbox = new byte[16, 16] { {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
                                                 {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                                                    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                                                 {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                                                    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                                                    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                                                    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                                                    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                                                    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                                                    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                                                    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                                                    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                                                    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                                                    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                                                    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                                                    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16} };
        int Rcon_index = 0;
        byte[,] Rcon = new byte[4, 10] { {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
                                                 {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                                 {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                                 {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
        byte[,] key_expansion = new byte[44, 4];
        byte[] Rotword(byte[] word)
        {
            byte first = word[0];
            for (int i = 0; i < 3; i++)
                word[i] = word[i + 1];
            word[3] = first;
            return word;
        }
        byte[] Sub_Byte(byte[] word)
        {
            byte[] ret = new byte[4];
            int newI;
            int newJ;
            for (int i = 0; i < 4; i++)
            {
                string tmp = Convert.ToString(word[i], 16);
                if (tmp.Length == 1)
                {
                    newI = 0;
                    newJ = Convert.ToInt32(tmp[0].ToString(), 16);
                }
                else
                {
                    newI = Convert.ToInt32(tmp[0].ToString(), 16);
                    newJ = Convert.ToInt32(tmp[1].ToString(), 16);
                }
                ret[i] = sbox[newI, newJ];
            }
            return ret;
        }
        byte[] xor(byte[] first, byte[] second, byte[] third, int is_multiple_of_4)
        {
            byte[] ret = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                string tmp;
                if (is_multiple_of_4 == 0)
                    tmp = Convert.ToString(first[i] ^ second[i], 16);
                else
                    tmp = Convert.ToString(first[i] ^ second[i] ^ third[i], 16);

                ret[i] = Convert.ToByte(tmp, 16);

            }


            return ret;
        }

        string makeMatrixString(byte[,] matrix)
        {
            StringBuilder str = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    var temp = Convert.ToString(matrix[j, i], 16);
                    if (temp.Length < 2)
                    {
                        str.Append("0" + temp);
                    }
                    else str.Append(temp);
                }
            }
            return str.ToString().ToUpper().Insert(0, "0x");
        }

        byte[,] makeByteMatrix(string str)
        {
            byte[,] matrix = new byte[4, 4];

            int k = 2;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string tmp = "0x" + str[k] + str[k + 1];
                    matrix[i, j] = Convert.ToByte(tmp, 16);
                    k += 2;
                }
            }
            return matrix;
        }

        byte[,] makeByteMatrix2(string str)
        {
            byte[,] matrix = new byte[4, 4];

            int k = 2;
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    string tmp = "0x" + str[k] + str[k + 1];
                    matrix[j, i] = Convert.ToByte(tmp, 16);
                    k += 2;
                }
            }
            return matrix;
        }

        void put_key(string key)
        {
            byte[,] key_arr = new byte[4, 4];
            key_arr = makeByteMatrix2(key);
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    key_expansion[i, j] = key_arr[i, j];

        }
        byte[,] get_key_matrix(int index)
        {
            byte[,] mat = new byte[4, 4];
            int row = 0, col = 0;
            for (int i = index * 4; i < index * 4 + 4; i++)
            {
                col = 0;
                for (int j = 0; j < 4; j++)
                {
                    mat[col, row] = key_expansion[i, j];
                    col++;
                }
                row++;
            }
            return mat;
        }
        byte[,] RoundKey(byte[,] matrix, int Round_index)
        {
            byte[,] key_round;
            key_round = get_key_matrix(Round_index);

            print_mat(key_round);

            print_mat(matrix);

            string tmp;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tmp = Convert.ToString(key_round[i, j] ^ matrix[i, j], 16);
                    key_round[i,j] = Convert.ToByte(tmp, 16);
                }
            }
            return key_round;
        }
        void implement_key_expansion()
        {
            byte[] first = new byte[4];
            byte[] second = new byte[4];
            byte[] third = new byte[4];
            byte[] final = new byte[4];
            for (int i = 4; i < 44; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    first[j] = key_expansion[i - 1, j];
                    second[j] = key_expansion[i - 4, j];
                    if (Rcon_index < 10)
                        third[j] = Rcon[j, Rcon_index];
                }
                if (i % 4 == 0)
                {
                    // Console.WriteLine(i);
                    Rcon_index++;
                    first = Rotword(first);
                    first = Sub_Byte(first);
                    final = xor(first, second, third, 1);
                }
                else
                    final = xor(first, second, third, 0);

                for (int j = 0; j < 4; j++)
                {
                    // Console.Write(key_expansion[i,j]);
                    key_expansion[i, j] = final[j];
                }

            }
        }
        void print_key_matrix()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 44; j++)
                {
                    Console.Write(string.Join(", ", key_expansion[j, i].ToString("X2")));
                    Console.Write(" ");
                }
                Console.WriteLine();
            }
        }
        void print_mat(byte[,] mat)
        {

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(string.Join(", ", mat[i, j].ToString("X2")));
                    Console.Write(" ");
                }
                Console.WriteLine();
            }

            Console.WriteLine("");
        }
        byte[,] galoisField = new byte[4, 4] { {0x02, 0x03, 0x01, 0x01},
                                                            {0x01, 0x02, 0x03, 0x01},
                                                            {0x01, 0x01, 0x02, 0x03},
                                                            {0x03, 0x01, 0x01, 0x02} };

        byte[,] mixCols(byte[,] shiftedmatrix)
        {
            List<byte> mixedMat = new List<byte>();
            byte[] arrayXor = new byte[4];
            byte[,] mixedColsMat = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        if (galoisField[j, k] == 2)
                        {
                            UInt32 temp = Convert.ToUInt32(shiftedmatrix[k, i] << 1);
                            arrayXor[k] = (byte)(temp & 0xFF);
                            if (shiftedmatrix[k, i] > 127)
                                arrayXor[k] = Convert.ToByte(arrayXor[k] ^ 27);
                        }
                        if (galoisField[j, k] == 3)
                        {
                            UInt32 temp = Convert.ToUInt32(shiftedmatrix[k, i] << 1);
                            arrayXor[k] = (byte)(temp & 0xFF);
                            if (shiftedmatrix[k, i] > 127)
                                arrayXor[k] = Convert.ToByte(arrayXor[k] ^ 27);
                            arrayXor[k] = Convert.ToByte(arrayXor[k] ^ shiftedmatrix[k, i]);
                        }

                        if (galoisField[j, k] == 1)
                        {
                            arrayXor[k] = shiftedmatrix[k, i];
                        }
                    }
                    var cell = arrayXor[0] ^ arrayXor[1] ^ arrayXor[2] ^ arrayXor[3];
                    mixedColsMat[j, i] = Convert.ToByte(cell);
                }
            }
            return mixedColsMat;
        }
        byte[,] initial_round(byte[,] state)
        {
            string tmp;
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    tmp = Convert.ToString(state[j, i] ^ key_expansion[i, j], 16);

                    state[j, i] = Convert.ToByte(tmp, 16);
                }
            }
            return state;
        }
        byte[,] substituteMatrix(byte[,] matrix)
        {
            byte[,] newMatrix = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string tmp = Convert.ToString(matrix[i, j], 16);
                    int newI, newJ;
                    if (tmp.Length == 1)
                    {
                        newI = 0;
                        newJ = Convert.ToInt32(tmp[0].ToString(), 16);
                    }
                    else
                    {
                        newI = Convert.ToInt32(tmp[0].ToString(), 16);
                        newJ = Convert.ToInt32(tmp[1].ToString(), 16);
                    }


                    newMatrix[i, j] = sbox[newI, newJ];
                }
            }
            return newMatrix;
        }

        byte[] shiftRow(byte[] row, int n)
        {
            UInt32 number = 0;
            for (int i = 0; i < 4; i++)
            {
                
                number += Convert.ToUInt32(row[i]);
                if (i != 3) number = number << 8;
            }
            number = ((number << (n*8)) | (number) >> (32 - (n*8)));

            byte[] newRow = new byte[4];
            for (int i = 3; i >= 0; i--)
            {
                newRow[i] = (byte)(number & 0xFF);
                number = number >> 8;
            }
            return newRow;
        }
        byte[,] shiftMatrix(byte[,] matrix)
        {
            byte[,] newMatrix = new byte[4, 4];
            byte[] row = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    row[j] = matrix[i, j];
                }
                row = shiftRow(row, i);
                for (int j = 0; j < 4; j++)
                {
                    newMatrix[i, j] = row[j];
                }
            }
            return newMatrix;
        }
        byte[,] xorMatrix(byte[,] matrix, byte[,] key)
        {
            byte[,] newMatrix = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string tmp = Convert.ToString(matrix[i, j] ^ key[i, j], 16);
                    newMatrix[i, j] = Convert.ToByte(tmp, 16);
                }
            }
            return newMatrix;
        }
        byte[,] finalRound(byte[,] state)
        {
            state = substituteMatrix(state);
            print_mat(state);
            //print_key_matrix();
            state = shiftMatrix(state);
            print_mat(state);
            //print_key_matrix();
            state = RoundKey(state, 10);
            print_mat(state);
            //print_key_matrix();
            return state;
        }
        byte[,] main_rounds(byte[,] state, int round)
        {

            state = substituteMatrix(state);
            print_mat(state);
            //print_key_matrix();
            state = shiftMatrix(state);
            print_mat(state);
            //print_key_matrix();
            state = mixCols(state);
            print_mat(state);
            //print_key_matrix();
            state = RoundKey(state, round);
            print_mat(state);
            //print_key_matrix();
            return state;
        }
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            byte[,] state = makeByteMatrix(plainText);
            put_key(key);
            implement_key_expansion();
            state = initial_round(state);

            for (int i = 1; i < 10; i++)
            {
                state = main_rounds(state, i);
            }

            state = finalRound(state);
            return makeMatrixString(state);
        }
    }
}
