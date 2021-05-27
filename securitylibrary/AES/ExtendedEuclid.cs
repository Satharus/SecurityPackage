using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            List<int> q = new List<int>();
            List<List<int>> aTable = new List<List<int>>();
            List<List<int>> bTable = new List<List<int>>();
            List<int> temp = new List<int>();
            // A1, 2, 3 list
            temp.Add(1);
            temp.Add(0);
            temp.Add(baseN);
            aTable.Add(new List<int>(temp));
            temp.Clear();
            // B1, 2, 3 list
            temp.Add(0);
            temp.Add(1);
            temp.Add(number);
            bTable.Add(new List<int>(temp));
            // temp.Clear();
            int k = 0;
            while (bTable[k][2] != 0 && bTable[k][2] != 1)
            {
                q.Add(aTable[k][2] / bTable[k][2]);
                // Fill A1, 2, 3 list
                temp.Add(bTable[k][0]);
                temp.Add(bTable[k][1]);
                temp.Add(bTable[k][2]);
                aTable.Add(new List<int>(temp));
                temp.Clear();
                // Fill B1, 2, 3 list
                temp.Add(aTable[k][0] - q[k] * bTable[k][0]);
                temp.Add(aTable[k][1] - q[k] * bTable[k][1]);
                temp.Add(aTable[k][2] - q[k] * bTable[k][2]);
                bTable.Add(new List<int>(temp));
                temp.Clear();
                k++;
            }
            if (bTable[k][2] == 1)
            {
                if (bTable[k][1] < 0)
                {
                    while (bTable[k][1] < 0)
                    {
                        bTable[k][1]+=baseN;
                    }
                }
                return bTable[k][1];
            }
            return -1;
        }
    }
}
