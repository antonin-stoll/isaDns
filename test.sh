echo "----------------test 1---------------"
echo "./dns -s kazi.fit.vutbr.cz -r www.fit.vut.cz"
./dns -s kazi.fit.vutbr.cz -r www.fit.vut.cz

echo "----------------test 2---------------"
echo "./dns -r -s kazi.fit.vutbr.cz www.github.com"
./dns -r -s kazi.fit.vutbr.cz www.github.com

echo "----------------test 3---------------"
echo "./dns -s 1.1.1.1 google.com"
./dns -s 1.1.1.1 google.com

echo "----------------test 4---------------"
echo "./dns -s 1.1.1.1 142.251.37.110 -x"
./dns -s 1.1.1.1 142.251.37.110 -x

echo "----------------test 5---------------"
echo "./dns -s 1.1.1.1 -x 147.229.2.90 -r"
./dns -s 1.1.1.1 -x 147.229.2.90 -r

echo "----------------test 6---------------"
echo "./dns -6 -s 1.1.1.1 -r www.google.com"
./dns -6 -s 1.1.1.1 -r www.google.com
