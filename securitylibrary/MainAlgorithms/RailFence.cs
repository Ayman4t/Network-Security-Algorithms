using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 2;
            int k = 0;
            double P_length = plainText.Length;
            while (true)
            {
                int col_num = (int)Math.Ceiling(P_length / key);
                string cipherTexttemp = "";

                int counter = 0;
                char[,] table_of_words = new char[key, col_num];

                if (k <= P_length)
                {
                    for (int j = 0; j < col_num; j++)
                    {
                        for (int i = 0; i < key; i++)
                        {
                            if (counter >= P_length)
                            {
                                table_of_words[i, j] = 'x';
                            }
                            else
                            {
                                table_of_words[i, j] = plainText[counter];
                                counter++;
                            }
                        }
                    }
                    for (int i = 0; i < key; i++)
                    {
                        for (int j = 0; j < col_num; j++)
                        {
                            int condition = (j + 1) * (i + 1);
                            if (condition > P_length)
                            {
                                break;
                            }
                            else
                            {
                                if (table_of_words[i, j] == 'x')
                                {
                                    continue;
                                }
                                else
                                {
                                    cipherTexttemp += table_of_words[i, j];
                                }
                            }
                        }
                    }
                    if (cipherTexttemp.ToUpper() == cipherText)
                    {
                        break;
                    }
                    else
                    {
                        key++;
                    }
                    k++;
                }
                else
                {
                    break;
                }
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            double C_length = cipherText.Length;
            int col_num = (int)Math.Ceiling(C_length / key);

            string plainText = "";

            int counter = 0, i = 0, j = 0;
            char[,] table_of_words = new char[key, col_num];
            while (true)
            {
                if (i < key)
                {

                    for (j = 0; j < col_num; j++)
                    {
                        if (counter >= C_length)
                        {
                            break;
                        }
                        table_of_words[i, j] = cipherText[counter];
                        counter++;
                    }
                    i++;
                }
                else
                {
                    break;
                }
            }
            j = 0;

            while (j < col_num)
            {
                for (i = 0; i < key; i++)
                {
                    int condition = (j + 1) * (i + 1);
                    if (condition > C_length)
                    {
                        break;
                    }
                    plainText += table_of_words[i, j]; ;

                }
                j++;
            }

            return plainText.ToLower();
        }

        public string Encrypt(string plainText, int key)
        {
            double P_length = plainText.Length;
            int col_num = (int)Math.Ceiling(P_length / key);


            string cipherText = "";
            int counter = 0, g = 0, i = 0, j = 0;
            char[,] table_of_words = new char[key, col_num];
            char[,] cipherText_of_words = new char[key, col_num];
            while (j < col_num)
            {
                for (i = 0; i < key; i++)
                {
                    if (counter >= P_length)
                    {
                        break;
                    }
                    table_of_words[i, j] = plainText[counter];
                    counter++;

                }
                j++;
            }
            i = 0;
            while (true)
            {
                if (i < key)
                {
                    for (j = 0; j < col_num; j++)
                    {
                        int condition = (j + 1) * (i + 1);
                        if (condition > P_length)
                        {
                            break;
                        }
                        cipherText += table_of_words[i, j];
                    }
                    i++;
                }
                else
                {
                    break;
                }
            }
            return cipherText.ToUpper();
        }
    }
}

