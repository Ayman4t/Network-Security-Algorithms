using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            Dictionary<char, char> mapping = new Dictionary<char, char>();
            cipherText = cipherText.ToUpper();
            plainText = plainText.ToUpper();
            for (int i = 0; i < plainText.Length; i++)
            {
                mapping[plainText[i]] = cipherText[i];
            }
            string missingChars = new string(
                Enumerable.Range('A', 26)
                          .Select(c => (char)c)
                          .Where(c => !cipherText.Contains(c))
                          .ToArray());
            int missingIndex = 0;
            foreach (char c in Enumerable.Range('A', 26).Select(c => (char)c))
            {
                if (!mapping.ContainsKey(c))
                {
                    mapping[c] = missingChars[missingIndex++];
                }
            }
            string key = string.Concat(mapping.OrderBy(pair => pair.Key).Select(pair => pair.Value));
            key = key.ToLower();
            return key;
        }
        public string Decrypt(string cipherText, string key)
        {
            string pt = "";
            Dictionary<char, char> map = new Dictionary<char, char>();
            key = key.ToLower();
            for (int i = 0; i < key.Length; i++)
            {
                char ch = (char)(i + 'a');
                char encryptedChar = key[i];
                map[encryptedChar] = ch;
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                char encryptedChar = cipherText[i];
                char decryptedChar;
                if (char.IsLetter(encryptedChar))
                {
                    decryptedChar = map.ContainsKey(char.ToLower(encryptedChar)) ? map[char.ToLower(encryptedChar)] : encryptedChar;
                    if (char.IsUpper(encryptedChar))
                        decryptedChar = char.ToUpper(decryptedChar);
                }
                else
                {
                    decryptedChar = encryptedChar;
                }
                pt += decryptedChar;
            }

            return pt;
        }

        public string Encrypt(string plainText, string key)
        {
            string ct = "";
            Dictionary<char, char> mapping = new Dictionary<char, char>();
            key = key.ToLower();
            for (char c = 'a'; c <= 'z'; c++)
            {
                mapping[c] = key[c - 'a'];
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                char ch = plainText[i];
                char encryptedChar;
                if (char.IsLetter(ch))
                {
                    encryptedChar = mapping.ContainsKey(char.ToLower(ch)) ? mapping[char.ToLower(ch)] : ch;
                    if (char.IsUpper(ch))
                        encryptedChar = char.ToUpper(encryptedChar);
                }
                else
                {
                    encryptedChar = ch;
                }
                ct += encryptedChar;
            }

            return ct;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string alphabetFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            Dictionary<char, int> cipherAlphaFreq = new Dictionary<char, int>();
            SortedDictionary<char, char> keyTable = new SortedDictionary<char, char>();
            cipher = cipher.ToLower();
            foreach (char c in cipher)
            {
                if (!cipherAlphaFreq.ContainsKey(c))
                {
                    cipherAlphaFreq.Add(c, 0);
                }
                else
                {
                    cipherAlphaFreq[c]++;
                }
            }
            cipherAlphaFreq = cipherAlphaFreq.OrderByDescending(x => x.Value).ToDictionary(x => x.Key, x => x.Value);
            int counter = 0;
            foreach (var item in cipherAlphaFreq)
            {
                keyTable.Add(item.Key, alphabetFreq[counter]);
                counter++;
            }
            string key = new string(cipher.Select(c => keyTable[c]).ToArray());
            return key;
        }
    }
}
