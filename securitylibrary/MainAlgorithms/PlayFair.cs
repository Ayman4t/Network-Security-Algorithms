using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;



namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {

            string plainText = "";
            string matrix = null;
            cipherText = cipherText.ToLower();
            string alphabetArray = "abcdefghiklmnopqrstuvwxyz";
            char[] alphabetletters = alphabetArray.ToCharArray();
            List<int> indecies = new List<int>();

            //fill matrix with key
            for (int i = 0; i < key.Length; i++)
            {
                if ((matrix == null))
                    matrix += key[i];
            }

            for (int i = 0; i < key.Length; i++)
            {
                if ((!matrix.Contains(key[i])))
                {
                    matrix += key[i];
                }
            }

            //fill matrix with alphabet if key finished
            int ii = 0;
            int k = alphabetletters.Length;
            while (ii < k)
            {
                if (!matrix.Contains(alphabetletters[ii]))
                    matrix += alphabetletters[ii];
                ii++;
            }

            for (int j = 0; j < cipherText.Length; j += 2)
            {
                int FirstPos = matrix.IndexOf(cipherText[j]);
                int SecondPos = matrix.IndexOf(cipherText[j + 1]);
                int First_Row = FirstPos / 5;
                int Second_Row = SecondPos / 5;
                int First_Column = FirstPos % 5;
                int Second_Cloumn = SecondPos % 5;
                if (First_Column == Second_Cloumn)
                {
                    FirstPos -= 5;
                    SecondPos -= 5;
                }
                else
                {
                    if (First_Row == Second_Row)
                    {

                        if (Second_Cloumn == 0)
                            SecondPos += 4;
                        else
                            SecondPos -= 1;
                        if (First_Column == 0)
                            FirstPos += 4;
                        else
                            FirstPos -= 1;
                    }
                    else
                    {
                        if (First_Row < Second_Row)
                        {
                            FirstPos -= First_Column - Second_Cloumn;
                            SecondPos += First_Column - Second_Cloumn;

                        }

                        else
                        {
                            FirstPos += Second_Cloumn - First_Column;
                            SecondPos -= Second_Cloumn - First_Column;
                        }
                    }
                }
                if (FirstPos < 0)
                    FirstPos = matrix.Length + FirstPos;

                if (SecondPos < 0)
                    SecondPos = matrix.Length + SecondPos;

                plainText += matrix[FirstPos].ToString() + matrix[SecondPos].ToString();

            }
            int p = 1;
            int c = plainText.Length;
            while (p < c)
            {
                if (((p + 1) < plainText.Length))
                {
                    if ((plainText[p - 1] == plainText[p + 1]))
                    {
                        if ((plainText[p] == 'x'))
                        {
                            indecies.Add(p);
                        }
                    }
                }
                p += 2;
            }
            //same letter 


            //lenght odd
            if (((plainText.Length % 2) == 0))
            {
                if ((plainText[plainText.Length - 1] == 'x'))
                {
                    plainText = plainText.Remove(plainText.Length - 1, 1);
                }
            }


            int count = 0;
            for (int j = 0; j < indecies.Count; j++)
            {
                int i = indecies[j];
                plainText = plainText.Remove(i - count, 1);
                count++;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {

            Dictionary<char, int> mymap = new Dictionary<char, int>();

            for (char n = 'a'; n <= 'z'; n++)
            {
                mymap.Add(n, 0);
            }


            string plain = plainText.ToLower();
            string mykey = key.ToLower();
            string newkey = "";

            for (int i = 0; i < mykey.Length; ++i)
            {
                mymap[mykey[i]]++;
                if (mymap[mykey[i]] == 1)
                {
                    newkey += mykey[i];
                }
            }

            Console.WriteLine(newkey);

            string tempstr = "";
            foreach (var c in mymap)
            {
                if (c.Value == 0)
                {
                    if (c.Key == 'j')
                        continue;
                    else

                        tempstr += c.Key;

                }
                else
                    continue;
            }
            Console.WriteLine(tempstr);

            char[,] matrix = new char[5, 5];
            int idx1 = 0;
            int idx2 = 0;
            for (int i = 0; i < 5; ++i)
            {
                for (int j = 0; j < 5; ++j)
                {
                    if (idx1 != newkey.Length)
                    {
                        matrix[i, j] = newkey[idx1];
                        idx1++;

                    }
                    else
                    {
                        matrix[i, j] = tempstr[idx2];
                        idx2++;
                    }
                }
            }
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    Console.Write(matrix[i, j] + " ");
                }
                Console.WriteLine();
            }

            int idxi = 0, idxj = 1;
            char[] act = new char[2];
            string result = "";
            bool still = false;
            int stop = 0;
            while (true)
            {

                if (plain[idxi] != plain[idxj])
                {
                    act[0] = plain[idxi];
                    act[1] = plain[idxj];
                    if (act[0] == 'j')
                        act[0] = 'i';
                    if (act[1] == 'j')
                        act[1] = 'j';
                    idxi += 2;
                    idxj += 2;
                    stop += 2;
                }
                else
                {
                    act[0] = plain[idxi];
                    act[1] = 'x';
                    if (act[0] == 'j')
                        act[0] = 'i';
                    idxi += 1;
                    idxj += 1;
                    stop += 1;
                }

                int i1 = 0, j1 = 0;
                bool flag1 = true;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (act[0] == matrix[i, j])
                        {
                            i1 = i;
                            j1 = j;
                            flag1 = false;
                            break;
                        }
                    }
                    if (!flag1)
                        break;
                }

                int i2 = 0, j2 = 0;
                bool flag2 = true;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (act[1] == matrix[i, j])
                        {
                            i2 = i;
                            j2 = j;
                            flag2 = false;
                            break;
                        }
                    }
                    if (!flag2)
                        break;
                }

                if (i1 == i2)
                {
                    result += matrix[i1, (j1 + 1) % 5];
                    result += matrix[i2, (j2 + 1) % 5];
                }
                else if (j1 == j2)
                {
                    result += matrix[(i1 + 1) % 5, j1];
                    result += matrix[(i2 + 1) % 5, j2];
                }
                else if (i1 != i2 && j1 != j2)
                {
                    result += matrix[i1, j2];
                    result += matrix[i2, j1];
                }


                //Console.WriteLine(result);

                if (stop >= plain.Length - 1)
                    //still = true;
                    break;

            }


            if (stop == plain.Length - 1)
            {
                act[0] = plain[plain.Length - 1];
                act[1] = 'x';
                int i1 = 0, j1 = 0;
                bool flag1 = true;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (act[0] == matrix[i, j])
                        {
                            i1 = i;
                            j1 = j;
                            flag1 = false;
                            break;
                        }
                    }
                    if (!flag1)
                        break;
                }

                int i2 = 0, j2 = 0;
                bool flag2 = true;
                for (int i = 0; i < 5; i++)
                {
                    for (int j = 0; j < 5; j++)
                    {
                        if (act[1] == matrix[i, j])
                        {
                            i2 = i;
                            j2 = j;
                            flag2 = false;
                            break;
                        }
                    }
                    if (!flag2)
                        break;
                }

                if (i1 == i2)
                {
                    result += matrix[i1, (j1 + 1) % 5];
                    result += matrix[i2, (j2 + 1) % 5];
                }
                else if (j1 == j2)
                {
                    result += matrix[(i1 + 1) % 5, j1];
                    result += matrix[(i2 + 1) % 5, j2];
                }
                else if (i1 != i2 && j1 != j2)
                {
                    result += matrix[i1, j2];
                    result += matrix[i2, j1];
                }

            }
            return result;


        }
    }
}