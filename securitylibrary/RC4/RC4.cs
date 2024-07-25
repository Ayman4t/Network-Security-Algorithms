using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {

            int j = 0;
            int i = 0;
            bool hexa = false;
            string temp = "";
            int[] S = new int[256];
            int[] T = new int[256];
            for (i = 0; i < 256; i++)
            {
                S[i] = i;
            }

            if (cipherText[0] == '0')
            {
                if (cipherText[1] == 'x')
                {
                    hexa = true;
                    string h;

                    for (int v = 2; v < cipherText.Length; v += 2)
                    {
                        string hexValue = cipherText.Substring(v, 2);
                        char cha = (char)Convert.ToInt32(hexValue, 16);
                        temp += cha;
                    }
                    cipherText = temp;
                    temp = "";
                    for (int b = 2; b < key.Length; b += 2)
                    {
                        string hexValue = key.Substring(b, 2);
                        char cha = (char)Convert.ToInt32(hexValue, 16);
                        temp += cha;
                    }
                    key = temp;
                }


            }



            while (j < 256)
            {
                int len_key = key.Length;
                for (i = 0; i < len_key; i++)
                {
                    if (j == 256)
                        break;
                    T[j] = key[i];
                    j++;
                }
            }
            j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                int temp4;
                temp4 = S[i];
                S[i] = S[j];
                S[j] = temp4;

            }

            i = 0;
            j = 0;
            int l = 0;
            int t;
            int[] k = new int[cipherText.Length];
            int len_cipher = cipherText.Length;
            while (l < len_cipher)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;
                int temp5;
                temp5 = S[i];
                S[i] = S[j];
                S[j] = temp5;

                t = (S[i] + S[j]) % 256;
                k[l] = S[t];
                l++;
            }




            //l = 0;
            int[] p = new int[cipherText.Length];
            int[] c = new int[cipherText.Length];
            for (int iii = 0; iii < cipherText.Length; iii++)
            {
                c[iii] = cipherText[iii] ^ k[iii];
            }




            if (hexa)
            {
                string hexastring = "0x" + string.Concat(c.Select(integer => integer.ToString("X2")));
                return hexastring;
            }
            else
            {
                string s = new string(c.Select(ic => (char)ic).ToArray());
                return s;
            }
        }

        public override string Encrypt(string plainText, string key)
        {
            int j = 0;
            int i = 0;
            string temp = "";
            bool hexa = false;

            int[] S = new int[256];
            int m = 0;
            while (m < 256)
            {
                S[m] = m;
                m++;
            }

            int[] T = new int[256];


            if (plainText[0] == '0')
            {
                if (plainText[1] == 'x')
                {
                    hexa = true;
                    string h;
                    int len = plainText.Length;

                    int i_ = 2;
                    while (i_ < len)
                    {
                        string hexValue = plainText.Substring(i_, 2);
                        char cha = (char)Convert.ToInt32(hexValue, 16);
                        temp += cha;
                        i_ += 2;
                    }
                    plainText = temp;
                    temp = "";
                    int y = 2;
                    string tempKey = "";
                    while (y < key.Length)
                    {
                        string hexValue = key.Substring(y, 2);
                        char cha = (char)Convert.ToInt32(hexValue, 16);
                        tempKey += cha;
                        y += 2;
                    }
                    key = tempKey;
                }
            }





            while (j < 256)
            {
                int lenk = key.Length;
                int o = 0;
                while (o < lenk)
                {
                    if (j == 256)
                        break;
                    T[j] = key[o];
                    o++;
                    j++;
                }
            }
            j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                int temp2;
                temp2 = S[i];
                S[i] = S[j];
                S[j] = temp2;
            }

            i = 0;
            j = 0;
            int l = 0;
            int t;
            int[] k = new int[plainText.Length];
            while (l < plainText.Length)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;
                int temp3;
                temp3 = S[i];
                S[i] = S[j];
                S[j] = temp3;
                t = (S[i] + S[j]) % 256;
                k[l] = S[t];
                l++;
            }
            l = 0;
            int[] p = new int[plainText.Length];

            int[] c = new int[plainText.Length];
            for (int ii = 0; ii < plainText.Length; ii++)
            {
                c[ii] = plainText[ii] ^ k[ii];
            }





            if (hexa == true)
            {
                string hexastring = "0x" + string.Concat(c.Select(integer => integer.ToString("X")));
                return hexastring;
            }
            else
            {
                string s = string.Concat(c.Select(ic => (char)ic));
                return s;
            }
        }


    }
}

