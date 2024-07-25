using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int n = p * q;
            int result = 1;
            // pow(m , e)  n
            for (int i = 0; i < e; i++)
            {
                result *= M % n;
                if (result > n)
                    result %= n;
            }
            return result;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = p * q;
            int eular = (p - 1) * (q - 1);
            // d= e power -1 mod eular
            List<int> Q = new List<int>();

            List<int> A1 = new List<int>();
            List<int> A2 = new List<int>();
            List<int> A3 = new List<int>();

            List<int> B1 = new List<int>();
            List<int> B2 = new List<int>();
            List<int> B3 = new List<int>();

            int result = 1;
            Q.Add(0);
            A1.Add(1);
            A2.Add(0);
            A3.Add(eular);

            B1.Add(0);
            B2.Add(1);
            B3.Add(e);

            while (!B3.Contains(1))
            {
                Q.Add(A3.Last() / B3.Last());

                A1.Add(B1.Last());
                A2.Add(B2.Last());
                A3.Add(B3.Last());

                int first = A1[A1.Count - 2] - (Q[Q.Count - 1] * B1[B1.Count - 1]);
                int second = A2[A2.Count - 2] - (Q[Q.Count - 1] * B2[B2.Count - 1]);
                int third = A3[A3.Count - 2] - (Q[Q.Count - 1] * B3[B3.Count - 1]);

                B1.Add(first);
                B2.Add(second);
                B3.Add(third);
            }
            int d = B2.Last();
            while (d < 0)
                d += eular;
            for (int i = 0; i < d; i++)
            {
                result *= (int)(Math.Pow(C, 1) % n);
                if (result > n)
                    result %= n;
            }
            return result;
        }
    }
}
