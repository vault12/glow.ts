import { NaClDriver } from './nacl-driver.interface';
import { JsNaClDriver } from './js-nacl-driver';

/**
 * Facade singleton to access the NaCl driver.
 * Usage: call instance() with a chosen driver, and store the received object to perform further actions.
 */
export class NaCl {
  private static driverInstance?: NaClDriver;

  private constructor() {
  }

  public static instance(driver?: NaClDriver): NaClDriver {
    if (!this.driverInstance) {
      // fallback to the default JS driver
      this.driverInstance = driver || new JsNaClDriver();
    }

    return this.driverInstance;
  }
}
