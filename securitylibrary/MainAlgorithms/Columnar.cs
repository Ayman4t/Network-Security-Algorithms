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
            int row_num = 2;
            string cipher = cipherText.ToLower();
            double length = plainText.Length;
            double cipherlength = cipher.Length;
            List<int> Key = new List<int>();
            for (int k = 0; k <= plainText.Length; k++)
            {
                double rowdouble = length / row_num;
                int col_num = (int)Math.Ceiling(rowdouble);
                char[,] tablePlain = new char[row_num, col_num];
                char[,] tableCipher = new char[row_num, col_num];
                int counterPlain = 0;
                int counterCipher = 0;
                string[] Textplain = new string[col_num];
                string[] CipherText = new string[col_num];
                int i_row_num = 0;

                while (i_row_num < row_num)
                {
                    int j_col_num = 0;
                    while (j_col_num < col_num)
                    {
                        if (counterPlain >= length)
                        {
                            tablePlain[i_row_num, j_col_num] = 'x';
                        }
                        else
                        {
                            tablePlain[i_row_num, j_col_num] = plainText[counterPlain];
                            counterPlain++;
                        }
                        j_col_num++;
                    }
                    i_row_num++;
                }

                int v = 0;
                while (v < col_num)
                {
                    int i = 0;
                    while (i < row_num)
                    {
                        if (counterCipher >= cipherlength)
                        {
                            tableCipher[i, v] = 'e';
                        }
                        else
                        {
                            tableCipher[i, v] = cipher[counterCipher];
                            counterCipher++;
                        }
                        i++;
                    }
                    v++;
                }

                int n = 0;
                while (n < col_num)
                {

                    for (int j = 0; j < row_num; j++)
                    {
                        CipherText[n] += tableCipher[j, n];
                        Textplain[n] += tablePlain[j, n];

                    }
                    n++;
                }



                int counterMatching = 0;
                for (int i = 0; i < CipherText.Length; i++)
                {
                    for (int j = 0; j < Textplain.Length; j++)
                    {
                        if (CipherText[i] == Textplain[j])
                        {
                            counterMatching++;
                        }
                    }
                }
                if (counterMatching == col_num)
                {
                    for (int i = 0; i < Textplain.Length; i++)
                    {
                        for (int j = 0; j < CipherText.Length; j++)
                        {
                            if (Textplain[i] == CipherText[j])
                            {
                                Key.Insert(i, j + 1);
                                j = CipherText.Length;
                            }
                        }
                    }
                    break;
                }
                else
                {
                    row_num++;
                }
            }
            if (Key.Count == 0)
            {
                for (int i = 0; i < 100; i++)
                {
                    Key.Add(0);
                }
            }
            return Key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int thelogestcul = key.Max();
            double length = cipherText.Length;
            double row_double = length / thelogestcul;
            int row_num = (int)Math.Ceiling(row_double);
            string plainText = "";
            int count = 0;
            char[,] matric = new char[row_num, thelogestcul];
            char[,] Decrubtedmatric = new char[row_num, thelogestcul];

            int th = 0;
            while (th < thelogestcul)
            {
                int i = 0;
                while (i < row_num)
                {
                    if (count >= length)
                    {
                        break;
                    }
                    else
                    {
                        matric[i, th] = cipherText[count];
                        count++;
                    }
                    i++;
                }
                th++;
            }

            int kk = 0;
            while (kk < key.Count)
            {
                int j = 0;
                while (j < row_num)
                {
                    Decrubtedmatric[j, kk] = matric[j, key.ElementAt(kk) - 1];
                    j++;
                }
                kk++;
            }

            int ro = 0;
            while (ro < row_num)
            {
                int j = 0;
                while (j < thelogestcul)
                {
                    if (Decrubtedmatric[ro, j] == 'x')
                    {
                        continue;
                    }
                    else
                    {
                        plainText += Decrubtedmatric[ro, j];
                    }
                    j++;
                }
                ro++;
            }
            return plainText.ToLower();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int thelogestcul = key.Max();
            double length = plainText.Length;
            double row_double = length / thelogestcul;
            int numberOfraw = (int)Math.Ceiling(row_double);
            string cipherText = "";
            int count = 0;
            char[,] matrices = new char[numberOfraw, thelogestcul];
            Dictionary<int, int> dictionary = new Dictionary<int, int>();
            int ii = 0;
            while (ii < numberOfraw)
            {
                int jj = 0;
                while (jj < thelogestcul)
                {
                    if (count >= length)
                    {
                        matrices[ii, jj] = 'x';
                    }
                    else
                    {
                        matrices[ii, jj] = plainText[count];
                        count = count + 1;
                    }
                    jj++;
                }
                ii++;
            }

            int k = 0;
            while (k < key.Count)
            {
                dictionary.Add(key.ElementAt(k), k);
                k++;
            }
            k = 0;
            while (k < key.Count)
            {
                int index;
                dictionary.TryGetValue(k + 1, out index);
                int r = 0;
                while (r < numberOfraw)
                {
                    cipherText += matrices[r, index];
                    r++;
                }
                k++;
            }
            return cipherText.ToUpper();
        }
    }
}

