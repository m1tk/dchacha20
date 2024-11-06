set terminal svg size 1700,800
set output 'encrypt_plot.svg'

set multiplot layout 1,3
set bmargin at screen 0.3
set xlabel "Input Size (Bytes)" font ",16"
set ylabel "Throughput (Megabyte/Second)" font ",16"
set xtics font ",15"
set ytics font ",15"
set key outside bottom center maxrows 7 font ",16"

set xrange [0:1024]
set yrange [0:3500]

plot 'results/encrypt_OpenSSL ChaCha20.txt' using ($2 * 1048576):1 with linespoints title 'OpenSSL ChaCha20', \
'results/encrypt_RustCrypto ChaCha20.txt' using ($2 * 1048576):1 with linespoints title 'RustCrypto ChaCha20', \
'results/encrypt_Chacha20.txt' using ($2 * 1048576):1 with linespoints title 'Chacha20', \
'results/encrypt_DChacha20.txt' using ($2 * 1048576):1 with linespoints title 'DChacha20',

unset key
set xrange [1:10]
set xtics add ("1" 1)
set xlabel "Input Size (KiloBytes)" font ",16"

plot 'results/encrypt_OpenSSL ChaCha20.txt' using ($2 * 1024):1 with linespoints title 'OpenSSL ChaCha20', \
'results/encrypt_RustCrypto ChaCha20.txt' using ($2 * 1024):1 with linespoints title 'RustCrypto ChaCha20', \
'results/encrypt_Chacha20.txt' using ($2 * 1024):1 with linespoints title 'Chacha20', \
'results/encrypt_DChacha20.txt' using ($2 * 1024):1 with linespoints title 'DChacha20',

unset key
set xrange [1:1024]
set xtics add ("1" 1)
set xlabel "Input Size (MegaBytes)" font ",16"

plot 'results/encrypt_OpenSSL ChaCha20.txt' using 2:1 with linespoints title 'OpenSSL ChaCha20', \
'results/encrypt_RustCrypto ChaCha20.txt' using 2:1 with linespoints title 'RustCrypto ChaCha20', \
'results/encrypt_Chacha20.txt' using 2:1 with linespoints title 'Chacha20', \
'results/encrypt_DChacha20.txt' using 2:1 with linespoints title 'DChacha20'

unset multiplot

set terminal svg size 1700,800
set output 'decrypt_plot.svg'

set multiplot layout 1,3
set bmargin at screen 0.3
set xlabel "Input Size (Bytes)" font ",16"
set ylabel "Throughput (Megabyte/Second)" font ",16"
set xtics font ",15"
set ytics font ",15"
set key outside bottom center maxrows 7 font ",16"

set xrange [0:1024]
set yrange [0:3500]

plot 'results/decrypt_OpenSSL ChaCha20.txt' using ($2 * 1048576):1 with linespoints title 'OpenSSL ChaCha20', \
'results/decrypt_RustCrypto ChaCha20.txt' using ($2 * 1048576):1 with linespoints title 'RustCrypto ChaCha20', \
'results/decrypt_Chacha20.txt' using ($2 * 1048576):1 with linespoints title 'Chacha20', \
'results/decrypt_DChacha20.txt' using ($2 * 1048576):1 with linespoints title 'DChacha20'

unset key
set xrange [1:10]
set xtics add ("1" 1)
set xlabel "Input Size (KiloBytes)" font ",16"

plot 'results/decrypt_OpenSSL ChaCha20.txt' using ($2 * 1024):1 with linespoints title 'OpenSSL ChaCha20', \
'results/decrypt_RustCrypto ChaCha20.txt' using ($2 * 1024):1 with linespoints title 'RustCrypto ChaCha20', \
'results/decrypt_Chacha20.txt' using ($2 * 1024):1 with linespoints title 'Chacha20', \
'results/decrypt_DChacha20.txt' using ($2 * 1024):1 with linespoints title 'DChacha20'

unset key
set xrange [1:1024]
set xtics add ("1" 1)
set xlabel "Input Size (MegaBytes)" font ",16"

plot 'results/decrypt_OpenSSL ChaCha20.txt' using 2:1 with linespoints title 'OpenSSL ChaCha20', \
'results/decrypt_RustCrypto ChaCha20.txt' using 2:1 with linespoints title 'RustCrypto ChaCha20', \
'results/decrypt_Chacha20.txt' using 2:1 with linespoints title 'Chacha20', \
'results/decrypt_DChacha20.txt' using 2:1 with linespoints title 'DChacha20'
