#!/bin/bash
# rgb_confirm.sh - confirm correct RGB mapping for kbctrl

pause() {
    read -n 1 -s -r -p "Press any key to continue..."
    echo
}

echo "=== Confirming pure colors with corrected mapping ==="

echo "-> Red"
./kbctrl.py raw --packet "14 01 01 FF 00 00 00 00" --commit
pause

echo "-> Green"
./kbctrl.py raw --packet "14 01 01 00 FF 00 00 00" --commit
pause

echo "-> Blue"
./kbctrl.py raw --packet "14 01 01 00 00 FF 00 00" --commit
pause

echo "-> White (R+G+B)"
./kbctrl.py raw --packet "14 01 01 FF FF FF 00 00" --commit
pause

echo "=== Test complete ==="
