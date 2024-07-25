using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public static int Mod_Power(int num, int pow, int mod)
        {
            int result = 1;
            int i = 0;
            while (i < pow)
            {
                result = (result * num) % mod;
                i++;
            }
            return result;
        }

        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            List<int> result = new List<int>();

            //PUBLIC KEY
            int Y1 = Mod_Power(alpha, xa, q);
            int Y2 = Mod_Power(alpha, xb, q);
            // PRIVATE KEY
            int K1 = Mod_Power(Y1, xb, q);
            int K2 = Mod_Power(Y2, xa, q);

            result.Add(K1); result.Add(K2);
            return result;
        }
    }
}