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
        private byte[,] sbox = new byte[16,16] { {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
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

        private byte[,] mixColumnsMatrix = new byte[4, 4] { {0x02, 0x03, 0x01, 0x01},
                                                            {0x01, 0x02, 0x03, 0x01},
                                                            {0x01, 0x01, 0x02, 0x03},
                                                            {0x03, 0x01, 0x01, 0x02} };
        private int Rcon_index = 0;
        private byte[,] Rcon = new byte[4, 10] { {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 },
                                                 {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                                 {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
                                                 {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }};
        private byte[,] key_expansion = new byte[44, 4];
        private byte[] Rotword(byte[] word)
        {
            byte first = word[0];
            for (int i = 0; i < 3; i++)
                word[i] = word[i + 1];
            word[3] = first;
            return word;
        }
        private byte[] Sub_Byte(byte[] word)
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
        private byte[] xor(byte[] first, byte[] second, byte[] third, int is_multiple_of_4)
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
        private void put_key(string key)
        {
            byte[,] key_arr = new byte[4, 4];
            key_arr = makeByteMatrix(key);
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    key_expansion[i, j] = key_arr[i, j];

        }
        private void implement_key_expansion()
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
                    key_expansion[i, j] = final[j];
                }

            }
        }
        private byte[,] makeByteMatrix(string str)
        {
            bool hex = false;
            if (str[0] == '0' && str[1] == 'x')
            {
                hex = true;
                str = str.Substring(2, str.Length);
            }
            byte[,] matrix = new byte[4, 4];
            if (hex)
            {
                int k = 0;
                for (int j = 0; j < 4; j++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        string tmp = "0x" + str[k] + str[k+1];
                        matrix[i, j] = Convert.ToByte(tmp, 16);
                        k += 2;
                    }
                }
            }
            else
            {
                int k = 0;
                for (int j = 0; j < 4; j++)
                {
                    for (int i = 0; i < 4; i++)
                    {
                        byte tmp = (byte)str[k];
                        matrix[i, j] = tmp;
                        k++;
                    }
                }
            }
            return matrix;
        }
        private byte[,] xorMatrix(byte[,] matrix, byte[,] key)
        {
            byte[,] newMatrix = new byte[4,4];
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
        private byte[,] shiftMatrix(byte[,] matrix)
        {
            byte[,] newMatrix = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int newJ = (j - i) % 4;
                    if (newJ < 0) newJ += 4;
                    newMatrix[i, j] = matrix[i, newJ];
                }
            }
            return newMatrix;
        }
        private byte[] multiplyMatrix(byte[,] matrix, byte[] column)
        {
            byte[] newColumn = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    byte tmp = Convert.ToByte( Convert.ToString(matrix[i, j] * column[j], 16), 16 );
                    if (j == 0) newColumn[i] = tmp;    // If newColumn[i] is still empty, add the first multiplication result.
                    else newColumn[i] = Convert.ToByte( Convert.ToString(newColumn[i] ^ tmp, 16), 16 );
                }
            }
            return newColumn;
        }
        private byte[,] substituteMatrix(byte[,] matrix)
        {
            byte[,] newMatrix = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string tmp = Convert.ToString(matrix[i, j], 16);
                    int newI = Convert.ToInt32(tmp[0].ToString(), 16);
                    int newJ = Convert.ToInt32(tmp[1].ToString(), 16);
                    newMatrix[i, j] = sbox[newI, newJ];
                }
            }
                return newMatrix;
        }
          private byte[,] mixCols(byte[,] shiftedmatrix)
        {
            list<byte> mixedMat=new list<byte>();
            var arrayXor= new byte[4];
            byte[,] mixedColsMat=new byte[4,4];
            for(int i=0;i<4;i++)
            {
                for(int j=0;j<4;j++)
                {//i,j * mixcolumn[j,i]
                    for(int x =0;x<4;x++)
                    {
                        if(mixColumnsMatrix[j,x]==2)
                        {
                            arrayXor[x]=shiftedmatrix[x,i]<<1;
                            if(shiftedmatrix[x,i]>127)
                                arrayXor[x]=arrayXor[x]^27;
                        }
                        if(mixColumnsMatrix[j,x]==3)
                        {
                            arrayXor[x]=shiftedmatrix[x,i]<<1;
                            if(shiftedmatrix[x,i]>127)
                                arrayXor[x]=arrayXor[x]^27;
                            arrayXor[x]=arrayXor[x]^shiftedmatrix[x,i];
                        }


                        if(mixColumnsMatrix[j,x]==1)
                        {
                            arrayXor[x]=shiftedmatrix[x,i];
                        }
                    }
                    var cell=arrayXor[0]^arrayXor[1]^arrayXor[2]^arrayXor[3];
                    mixedColsMat[j,i]=cell;
                }
            }
            return mixedColsMat;
        }
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }
    }
}
