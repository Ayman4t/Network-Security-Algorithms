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

            int que = 0, A_1 = 1, A_2 = 0, A_3 = baseN, nB_1 = 0, nB_2 = 1, nB_3 = number;
            int temp1 = 0, temp2 = 0, temp3 = 0, res = -1;
            while (true)
            {
                que = A_3 / nB_3;
                temp1 = nB_1;
                temp2 = nB_2;
                temp3 = nB_3;
                nB_1 = A_1 - que * nB_1;
                nB_2 = A_2 - que * nB_2;
                nB_3 = A_3 - que * nB_3;
                A_1 = temp1;
                A_2 = temp2;
                A_3 = temp3;
                if (nB_3 == 1)
                {
                    if (nB_2 < 0)
                    {
                        nB_2 += baseN;
                    }
                    res = nB_2;
                    break;
                }
                else if (nB_3 == 0)
                {
                    break;
                }

            }
            return res;


        }
    }
}
