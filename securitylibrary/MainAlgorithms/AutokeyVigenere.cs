using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{



    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        Dictionary<char, int> mymap = new Dictionary<char, int>();
        char[] alphabet = new char[26];
        string lowInput = "";
        string lowkey = "";
        int[] pValues;
        int[] KeyValues;
        public void startfun()
        {
            for (int i = 0; i < 26; i++)
            {
                alphabet[i] = (char)('a' + i);
            }


            for (char n = 'a'; n <= 'z'; n++)
            {
                mymap.Add(n, n - 'a');
            }

        }
        public void lowercasefun(string plainText, string key)
        {
            lowInput = plainText.ToLower();
            string lowkey = key.ToLower();
            pValues = new int[lowInput.Length];
            int pi = 0;
            foreach (char ch in lowInput)
            {
                pValues[pi] = mymap[ch];

                pi += 1;
            }


            KeyValues = new int[lowkey.Length];
            int ki = 0;
            string result = "";
            foreach (char ch in lowkey)
            {
                KeyValues[ki] = mymap[ch];

                ki += 1;
            }


        }

        public string Analyse(string plainText, string cipherText)
        {
            startfun();


            string lowInput = plainText.ToLower();
            string lowkey = cipherText.ToLower();


            int[] pValues = new int[lowInput.Length];
            int pi = 0;
            foreach (char ch in lowInput)
            {
                pValues[pi] = mymap[ch];

                pi += 1;
            }


            int[] KeyValues = new int[lowkey.Length];
            int ki = 0;
            string result = "";
            foreach (char ch in lowkey)
            {
                KeyValues[ki] = mymap[ch];

                ki += 1;
            }

            int idx = 0;
            int idx2 = 0;
            bool flag = false;
            string tempstr = "";
            for (int i = 0; i < lowInput.Length; ++i)
            {
                int temp = 0;
                if (KeyValues[i] - pValues[i] < 0)
                    temp = (26 + (KeyValues[i] - pValues[i]));
                else
                    temp = (KeyValues[i] - pValues[i]) % 26;

                if (alphabet[temp] == lowInput[0])
                {


                    flag = true;
                }
                if (flag)
                {
                    if (alphabet[temp] == lowInput[idx])
                    {
                        tempstr += alphabet[temp];

                        idx++;

                    }
                    else
                    {
                        idx = 0;
                        result += tempstr;
                        flag = false;
                        tempstr = "";

                    }

                    // Console.WriteLine(alphabet[temp]+" break");
                    //break;

                }
                else
                {
                    result += alphabet[temp];
                }


            }

            return result;
        }

        public string Decrypt(string cipherText, string key)
        {


            startfun();
            lowercasefun(cipherText, key);
            string lowInput = cipherText.ToLower();


            string lowkey = key.ToLower();


            int[] pValues = new int[lowInput.Length];
            int pi = 0;
            foreach (char ch in lowInput)
            {
                pValues[pi] = mymap[ch];

                pi += 1;
            }


            int[] KeyValues = new int[lowkey.Length];
            int ki = 0;
            string result = "";
            foreach (char ch in lowkey)
            {
                KeyValues[ki] = mymap[ch];

                ki += 1;
            }

            int idx = 0;
            int idx2 = 0;
            if (lowInput.Length == lowkey.Length)
            {

                for (int i = 0; i < lowInput.Length; ++i)
                {
                    int temp = 0;
                    if (pValues[i] - KeyValues[i] < 0)
                        temp = (26 + (pValues[i] - KeyValues[i]));
                    else
                        temp = (pValues[i] - KeyValues[i]) % 26;
                    result += alphabet[temp];
                    Console.WriteLine(i + " " + " " + temp + " " + alphabet[temp]);
                }

            }


            else if (lowInput.Length > lowkey.Length)
            {
                int temp = 0;
                for (int i = 0; i < lowInput.Length; ++i)
                {

                    if (idx < lowkey.Length)
                    {

                        if (pValues[i] - KeyValues[i] < 0)
                            temp = (26 + (pValues[i] - KeyValues[i]));
                        else
                            temp = (pValues[i] - KeyValues[i]) % 26;
                        result += alphabet[temp];
                        idx++;

                    }
                    else
                    {
                        // if(idx2<result.Length)
                        //Console.WriteLine(result[idx2]+" "+idx2);
                        if (idx2 < result.Length)
                        {
                            if (pValues[i] - mymap[result[idx2]] < 0)
                                temp = (26 + (pValues[i] - mymap[result[idx2]]));
                            else
                                temp = (pValues[i] - mymap[result[idx2]]) % 26;
                            result += alphabet[temp];
                        }

                        idx2++;
                    }
                }

            }
            return result;
        }

        public string Encrypt(string plainText, string key)
        {

            startfun();
            string lowInput = plainText.ToLower();
            string lowkey = key.ToLower();


            int[] pValues = new int[lowInput.Length];
            int pi = 0;
            foreach (char ch in lowInput)
            {
                pValues[pi] = mymap[ch];

                pi += 1;
            }


            int[] KeyValues = new int[lowkey.Length];
            int ki = 0;
            string result = "";
            foreach (char ch in lowkey)
            {
                KeyValues[ki] = mymap[ch];

                ki += 1;
            }

            int idx = 0, idx2 = 0;
            if (lowInput.Length == lowkey.Length)
            {
                for (int i = 0; i < lowInput.Length; ++i)
                {
                    int temp = (KeyValues[i] + pValues[i]) % 26;
                    result += alphabet[temp];
                }

            }

            else if (lowInput.Length > lowkey.Length)
            {
                for (int i = 0; i < lowInput.Length; ++i)
                {
                    if (idx < lowkey.Length)
                    {
                        int temp = (KeyValues[i] + pValues[i]) % 26;
                        result += alphabet[temp];
                        idx++;

                    }
                    else
                    {
                        int temp = (pValues[idx2] + pValues[i]) % 26;
                        result += alphabet[temp];
                        idx2++;

                    }
                }

            }
            return result;

        }
    }
}
