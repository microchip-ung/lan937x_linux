// SPDX-License-Identifier: GPL-2.0
/* Microchip LAN937X switch driver register access through SPI
 * Copyright (C) 2019-2020 Microchip Technology Inc.
 */
#include <asm/unaligned.h>

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/regmap.h>
#include <linux/spi/spi.h>
#include <linux/of_device.h>

#include "ksz_common.h"

#define SPI_ADDR_SHIFT				24
#define SPI_ADDR_ALIGN				3
#define SPI_TURNAROUND_SHIFT		5

KSZ_REGMAP_TABLE(lan937x, 32, SPI_ADDR_SHIFT,
		 SPI_TURNAROUND_SHIFT, SPI_ADDR_ALIGN);

struct lan937x_chip_data {
	u32 chip_id;
	const char *dev_name;
	int num_vlans;
	int num_alus;
	int num_statics;
	int cpu_ports;
	int port_cnt;
};

static const struct of_device_id lan937x_dt_ids[];

static const struct lan937x_chip_data lan937x_switch_chips[] = {
	{
		.chip_id = 0x00937000,
		.dev_name = "LAN9370",
		.num_vlans = 4096,
		.num_alus = 1024,
		.num_statics = 256,
		/* can be configured as cpu port */
		.cpu_ports = 0x10,
		/* total port count */
		.port_cnt = 5,
	},
	{
		.chip_id = 0x00937100,
		.dev_name = "LAN9371",
		.num_vlans = 4096,
		.num_alus = 1024,
		.num_statics = 256,
		/* can be configured as cpu port */
		.cpu_ports = 0x30,
		/* total port count */
		.port_cnt = 6,
	},
	{
		.chip_id = 0x00937200,
		.dev_name = "LAN9372",
		.num_vlans = 4096,
		.num_alus = 1024,
		.num_statics = 256,
		/* can be configured as cpu port */
		.cpu_ports = 0x30,
		/* total port count */
		.port_cnt = 8,
	},
	{
		.chip_id = 0x00937300,
		.dev_name = "LAN9373",
		.num_vlans = 4096,
		.num_alus = 1024,
		.num_statics = 256,
		/* can be configured as cpu port */
		.cpu_ports = 0x38,
		/* total port count */
		.port_cnt = 5,
	},
	{
		.chip_id = 0x00937400,
		.dev_name = "LAN9374",
		.num_vlans = 4096,
		.num_alus = 1024,
		.num_statics = 256,
		/* can be configured as cpu port */
		.cpu_ports = 0x30,
		/* total port count */
		.port_cnt = 8,
	},

};

static int lan937x_spi_probe(struct spi_device *spi)
{
	struct regmap_config rc;
	struct ksz_device *dev;
	int i, ret;

	dev = ksz_switch_alloc(&spi->dev, spi);
	if (!dev)
		return -ENOMEM;

	for (i = 0; i < ARRAY_SIZE(lan937x_regmap_config); i++) {
		rc = lan937x_regmap_config[i];
		rc.lock_arg = &dev->regmap_mutex;
		dev->regmap[i] = devm_regmap_init_spi(spi, &rc);
		if (IS_ERR(dev->regmap[i])) {
			ret = PTR_ERR(dev->regmap[i]);
			dev_err(&spi->dev,
				"Failed to initialize regmap%i: %d\n",
				lan937x_regmap_config[i].val_bits, ret);
			return ret;
		}
	}

	if (spi->dev.platform_data)
		dev->pdata = spi->dev.platform_data;

	dev->irq = spi->irq;

	ret = lan937x_switch_register(dev);

	/* Main DSA driver may not be started yet. */
	if (ret)
		return ret;

	spi_set_drvdata(spi, dev);

	return 0;
}

int lan937x_check_device_id(struct ksz_device *dev)
{
	const struct lan937x_chip_data *dt_chip_data;
	const struct of_device_id *match;
	int i;

	dt_chip_data = of_device_get_match_data(dev->dev);

	if (!dt_chip_data)
		return -EINVAL;

	for (match = lan937x_dt_ids; match->compatible[0]; match++) {
		const struct lan937x_chip_data *chip_data = match->data;

		/* Check for chip id */
		if (chip_data->chip_id != dev->chip_id)
			continue;

		/* Check for Device Tree and Chip ID */
		if (dt_chip_data->chip_id != dev->chip_id) {
			dev_err(dev->dev, "Device tree specifies chip %s but found %s, please fix it!\n",
				dt_chip_data->dev_name, chip_data->dev_name);
			return -ENODEV;
		}

		break;
	}

	for (i = 0; i < ARRAY_SIZE(lan937x_switch_chips); i++) {
		const struct lan937x_chip_data *chip = &lan937x_switch_chips[i];

		if (dev->chip_id == chip->chip_id) {
			dev->name = chip->dev_name;
			dev->num_vlans = chip->num_vlans;
			dev->num_alus = chip->num_alus;
			dev->num_statics = chip->num_statics;
			dev->port_cnt = chip->port_cnt;
			dev->cpu_ports = chip->cpu_ports;
			break;
		}
	}

	/* no switch found */
	if (!dev->port_cnt)
		return -ENODEV;

	return 0;
}
EXPORT_SYMBOL(lan937x_check_device_id);

static int lan937x_spi_remove(struct spi_device *spi)
{
	struct ksz_device *dev = spi_get_drvdata(spi);

	if (dev)
		ksz_switch_remove(dev);

	return 0;
}

static void lan937x_spi_shutdown(struct spi_device *spi)
{
	struct ksz_device *dev = spi_get_drvdata(spi);

	if (dev && dev->dev_ops->shutdown)
		dev->dev_ops->shutdown(dev);
}

static const struct of_device_id lan937x_dt_ids[] = {
	{ .compatible = "microchip,lan9370", .data = &lan937x_switch_chips[0] },
	{ .compatible = "microchip,lan9371", .data = &lan937x_switch_chips[1] },
	{ .compatible = "microchip,lan9372", .data = &lan937x_switch_chips[2] },
	{ .compatible = "microchip,lan9373", .data = &lan937x_switch_chips[3] },
	{ .compatible = "microchip,lan9374", .data = &lan937x_switch_chips[4] },
	{},
};
MODULE_DEVICE_TABLE(of, lan937x_dt_ids);

static struct spi_driver lan937x_spi_driver = {
	.driver = {
		.name	= "lan937x-switch",
		.owner	= THIS_MODULE,
		.of_match_table = of_match_ptr(lan937x_dt_ids),
	},
	.probe	= lan937x_spi_probe,
	.remove	= lan937x_spi_remove,
	.shutdown = lan937x_spi_shutdown,
};

module_spi_driver(lan937x_spi_driver);

MODULE_ALIAS("spi:lan937x");

MODULE_AUTHOR("Prasanna Vengateshan Varadharajan <Prasanna.Vengateshan@microchip.com>");
MODULE_DESCRIPTION("Microchip LAN937x Series Switch SPI access Driver");
MODULE_LICENSE("GPL");
