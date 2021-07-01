cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/Documentation/devicetree/bindings/net/dsa/microchip,lan937x.yaml Documentation/devicetree/bindings/net/dsa/
cp -f ../../lan_937x_linux_dsa/src/kernels/masternet-next/MAINTAINERS .

git add MAINTAINERS Documentation/devicetree/bindings/net/dsa/microchip,lan937x.yaml

git commit -m "

dt-bindings: net: dsa: dt bindings for microchip lan937x

Documentation in .yaml format and updates to the MAINTAINERS
Also 'make dt_binding_check' is passed

"
